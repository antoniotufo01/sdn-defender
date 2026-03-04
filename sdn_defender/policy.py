# sdn_defender/policy.py
# ============================================================
#   MODULO POLICY ENGINE
#  Cuore decisionale del sistema SDN Defender:
#   - Analizza traffico per porta o per flusso
#   - Applica soglie dinamiche e rilevamento burst/stealth
#   - Gestisce rate limiting progressivo e blocchi temporanei
#   - Mitiga DDoS aggregati tramite BLACKHOLE multi-switch
# ============================================================

import math
import time
from collections import defaultdict
from ryu.lib import hub

from .models import Action, ActionType, PortKey, FlowKey


class Color:
    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"

class PolicyEngine:

    # ============================================================
    #   SEZIONE 1 — Inizializzazione e metodi ausiliari
    #  Gestisce lo stato interno, le strutture di supporto e il
    #  thread di esecuzione periodico del motore di policy.
    # ============================================================

    def __init__(self, datastore, enforcer, cfg):
        self.ds = datastore
        self.enforcer = enforcer
        self.cfg = cfg
        self._thread = None
        self._limit_counter = defaultdict(int)
        self._last_ddos_block_ts = {}
        self._last_block_ts = {}
        self._last_burst_state = {}   # --- per log solo su cambio stato ---

    # --- helper ---
    def _flow_sig(self, k: FlowKey):
        """Genera una firma univoca per un flusso (identificazione rapida)."""
        return (k.dpid, k.in_port, k.eth_src, k.eth_dst, k.ip_src, k.ip_dst, k.tp_dst)

    # ---- lifecycle ----
    # Avvia un thread periodico che richiama tick() a ogni intervallo
    # di polling, per valutare porte o flussi a seconda della modalità.
    def start(self):
        self._thread = hub.spawn(self._loop)

    def _loop(self):
        while True:
            self.tick()
            hub.sleep(self.cfg["poll_interval_s"])

    # ============================================================
    #   SEZIONE 2 — Ciclo principale di analisi (tick)
    #  tick():
    #     - scansiona tutte le porte o i flussi noti
    #     - esegue la logica di soglia dinamica o burst detection
    #     - attiva azioni BLOCK/LIMIT/UNBLOCK/BLACKHOLE via Enforcer
    # ============================================================

    def tick(self):
        scope = self.cfg.get("detect_scope", "port")
        if scope == "flow":
            for key in self.ds.get_all_flow_keys():
                self._evaluate_flow(key)
        else:
            for key in self.ds.get_all_port_keys():
                self._evaluate_port(key)

        # Analisi DDoS aggregato solo se attivata e in modalità flow
        if self.cfg.get("ddos_enable", True) and scope == "flow":
            self._detect_ddos_aggregate()

    # ============================================================
    #   SEZIONE 3 — Valutazione delle PORTE
    #  Analizza il traffico a livello L2 per ogni porta.
    #  Applica soglie dinamiche EWMA su rx_bps/tx_bps e decide
    #  se bloccare o sbloccare la porta in base ai contatori
    #  consecutivi e ai cooldown temporali.
    # ============================================================

    def _evaluate_port(self, key: PortKey):
        last = self.ds.get_last_port_delta(key)
        if not last:
            return

        # Aggiorna EWMA dinamica per questa porta
        self.ds.update_dynamic_threshold(key, last.rx_bps)

        # Recupera soglia dinamica (media * 1.2)
        dyn_thr = 1.2 * self.ds.get_dynamic_threshold(key)

        # Usa la soglia dinamica o quella statica minima
        threshold = max(dyn_thr, float(self.cfg["threshold_bps"]))

        over = (last.rx_bps > threshold) or (last.tx_bps > threshold)
        counter, alarm_on = self.ds.get_alarm_state(key)

        # Aggiorna contatori di superamento soglia
        if over and counter < self.cfg["consec_block"]:
            counter += 1
        elif not over and counter > 0:
            counter -= 1

        # Applica BLOCK dopo n superamenti consecutivi
        if counter == self.cfg["consec_block"] and not alarm_on:
            self.enforcer.enqueue(Action(ActionType.BLOCK, key))
            self._last_block_ts[self._flow_sig(key)] = time.time()
            alarm_on = True

        # Dopo il periodo di cooldown, UNBLOCK automatico
        elif alarm_on:
            last_block = self._last_block_ts.get(self._flow_sig(key), 0)
            age = time.time() - last_block
            if age >= self.cfg.get("unblock_cooldown_s", 15):
                self.enforcer.enqueue(Action(ActionType.UNBLOCK, key))
                alarm_on = False
                counter = 0

        self.ds.set_alarm_state(key, counter, alarm_on)

    # ============================================================
    #   SEZIONE 4 — Rilevamento Burst / Stealth
    #  Analizza i campioni più recenti per un flusso e calcola:
    #   - media, deviazione, coeff. di variazione (CV)
    #   - EWMA per andamento temporale
    #   - max/ewma ratio per identificare spike
    #  Permette di individuare pattern bursty anche sotto soglia.
    # ============================================================

    def _recent_flow_samples(self, key: FlowKey, window_s: float):
        """Restituisce i campioni più recenti entro la finestra temporale."""
        series = self.ds.get_flow_series(key)
        if not series:
            return []
        tmax = series[-1].ts
        return [d for d in series if (tmax - d.ts) <= window_s]

    def _stats_and_burst(self, samples, alpha: float = 0.2):
        """Calcola statistiche incrementali (media, std, EWMA, CV, picco)."""
        if not samples:
            return dict(n=0, mean=0.0, std=0.0, ewma=0.0, maxv=0.0, cv=0.0)

        vals = [float(s.bps) for s in samples]
        n = len(vals)
        m = 0.0
        m2 = 0.0
        k = 0
        ewma = None
        maxv = 0.0

        # Calcolo incrementale di media e varianza (Welford)
        for v in vals:
            k += 1
            delta = v - m
            m += delta / k
            m2 += delta * (v - m)
            ewma = v if ewma is None else (alpha * v + (1.0 - alpha) * ewma)
            if v > maxv:
                maxv = v

        mean = m
        var = (m2 / (k - 1)) if k > 1 else 0.0
        std = math.sqrt(var)
        cv = (std / mean) if mean > 0 else 0.0
        return dict(n=n, mean=mean, std=std, ewma=ewma, maxv=maxv, cv=cv)

    # ============================================================
    #   SEZIONE 5 — Valutazione dei SINGOLI FLUSSI
    #  Logica completa per decidere:
    #   - se un flusso è anomalo (over threshold o burst)
    #   - se limitare o bloccare in base a tentativi ripetuti
    #   - se sbloccare dopo il cooldown
    #  Include detection adattiva, rate limiting progressivo
    #  e prevenzione overblocking multi-switch.
    # ============================================================

    def _evaluate_flow(self, key: FlowKey):
        app = self.enforcer.app

        # 1) Esclusione di flussi in whitelist
        wl_cfg = set(self.cfg.get("whitelist_macs", []))
        if key.eth_src in wl_cfg or key.eth_dst in wl_cfg:
            return
        if self.ds.is_mac_whitelisted(key.eth_src) or self.ds.is_mac_whitelisted(key.eth_dst):
            return

        # 2) Ultima misura disponibile
        last = self.ds.get_last_flow_delta(key)
        if not last:
            return
        v = float(last.bps)

        # 3) Soglia dinamica adattiva (EWMA)
        self.ds.update_dynamic_flow_threshold(key, v)
        dyn_thr = 1.2 * self.ds.get_dynamic_flow_threshold(key)
        threshold = max(dyn_thr, float(self.cfg["threshold_bps"]))
        over = v > threshold

        # 4) Rilevamento di burst/stealth
        burst_window = float(self.cfg.get("burst_window_s", 6.0))
        samples = self._recent_flow_samples(key, burst_window)
        feats = self._stats_and_burst(samples, alpha=float(self.cfg.get("ewma_alpha", 0.2)))

        cv_min = float(self.cfg.get("burst_cv_min", 0.8))
        peak_ratio = float(self.cfg.get("burst_peak_ratio", 2.5))
        micro = float(self.cfg.get("micro_threshold_bps", 200_000))
        min_mean_for_burst = max(micro, float(self.cfg.get("min_mean_for_burst", 500_000)))

        bursty = False
        if feats["mean"] >= min_mean_for_burst:
            cv_ok = feats["cv"] >= cv_min
            peak_ok = (feats["ewma"] > 0 and (feats["maxv"] / feats["ewma"]) >= peak_ratio)
            if cv_ok and peak_ok:
                bursty = True

        # Log su cambi di stato (bursty/non-bursty)
        prev_state = self._last_burst_state.get(key, None)
        if prev_state is None or bursty != prev_state:
            self._last_burst_state[key] = bursty
            app.logger.info(
                f"{Color.CYAN}[BURST-STATE]{Color.RESET} {key} "
                f"changed to {'True' if bursty else 'False'} "
                f"(mean={int(feats['mean'])}, cv={feats['cv']:.2f}, "
                f"max/ewma={(feats['maxv']/(feats['ewma'] or 1)):.2f})"
            )

        # Log dedicato per burst sotto soglia
        if bursty and not over:
            app.logger.info(
                f"{Color.CYAN}[BURST DETECTED]{Color.RESET} {key} "
                f"mean={int(feats['mean'])} cv={feats['cv']:.2f} "
                f"max/ewma={(feats['maxv']/(feats['ewma'] or 1)):.2f}"
            )

        # 5) Decisione finale (LIMIT → BLOCK → UNBLOCK)
        is_attacky = over or (bursty and v > threshold)
        counter, alarm_on = self.ds.get_flow_alarm_state(key)

        # Contatori di superamento soglia
        if is_attacky and counter < self.cfg["consec_block"]:
            counter += 1
        elif not is_attacky and counter > 0:
            counter -= 1

        # --- Escalation di enforcement ---
        # Se superata la soglia o rilevato burst persistente,
        # applica LIMIT progressivo e successivo BLOCK dopo ripetuti fallimenti.
        if counter == self.cfg["consec_block"] and not alarm_on:
            reason = "RATE" if over else "BURST"
            ingress, ingress_port = app.find_ingress_by_mac(key.eth_src, key.eth_dst)
            if ingress is None:
                ingress, ingress_port = key.dpid, key.in_port
                app.logger.warning(f"[ENFORCE-FALLBACK] ingress unknown for {key.eth_src}->{key.eth_dst}")

            enforce_key = FlowKey(
                dpid=int(ingress),
                in_port=int(ingress_port) if ingress_port else key.in_port,
                eth_src=key.eth_src,
                eth_dst=key.eth_dst,
                ip_src=key.ip_src,
                ip_dst=key.ip_dst,
                tp_dst=key.tp_dst
            )

            sig = self._flow_sig(enforce_key)

            # --- Gestione progressiva ---
            # Se il flusso è sopra soglia ma non critico (< 3x thr),
            # viene inizialmente limitato. Dopo 5 LIMIT consecutivi
            # senza miglioramento, si procede al BLOCK definitivo.
            if over and v < 3 * threshold:
                now = time.time()
                if not hasattr(self, "_last_limit_ts"):
                    self._last_limit_ts = {}
                last_time = self._last_limit_ts.get(sig, 0)
                cooldown = 8
                if now - last_time < cooldown:
                    self._limit_counter[sig] = self._limit_counter.get(sig, 0) + 1
                    if self._limit_counter[sig] >= 5:
                        self.enforcer.enqueue(Action(ActionType.BLOCK, enforce_key))
                        app.logger.info(
                            f"{Color.RED}[BLOCKED]{Color.RESET} after {self._limit_counter[sig]} consecutive LIMITs {enforce_key}"
                        )
                        self._limit_counter[sig] = 0
                    return

                app.logger.info(
                    f"{Color.YELLOW}LIMIT FLOW {Color.RESET}{enforce_key} ({reason}) "
                    f"count={self._limit_counter[sig]} bps={int(v)} thr={int(threshold)} "
                    f"cv={feats['cv']:.2f} peak/ewma={(feats['maxv']/(feats['ewma'] or 1)):.2f} (ingress={ingress})"
                )

                self.enforcer.enqueue(Action(
                    kind=ActionType.LIMIT,
                    key=enforce_key,
                    params={"rate_kbps": int(self.cfg.get('limit_rate_kbps', 1000))}
                ))

                self._last_limit_ts[sig] = now
                self._limit_counter[sig] = self._limit_counter.get(sig, 0) + 1

                if self._limit_counter[sig] >= 5:
                    now = time.time()
                    if not hasattr(self, "_blocked_sig_ts"):
                        self._blocked_sig_ts = {}
                    last_b = self._blocked_sig_ts.get(sig, 0)
                    if now - last_b < 1.0:
                        return
                    self._blocked_sig_ts[sig] = now
                    self.enforcer.enqueue(Action(ActionType.BLOCK, enforce_key))
                    app.logger.info(
                        f"{Color.RED}[BLOCKED]{Color.RESET} after {self._limit_counter[sig]} consecutive LIMITs {enforce_key}"
                    )
                    self._limit_counter[sig] = 0

            self._last_block_ts[self._flow_sig(enforce_key)] = time.time()
            self.ds.set_flow_alarm_state(enforce_key, counter, True)
            return

        # --- Sblocco dopo cooldown ---
        elif alarm_on:
            last_block = self._last_block_ts.get(self._flow_sig(key), 0)
            age = time.time() - last_block
            if age >= self.cfg.get("unblock_cooldown_s", 15):
                ingress, ingress_port = app.find_ingress_by_mac(key.eth_src, key.eth_dst)
                if ingress is None:
                    ingress, ingress_port = key.dpid, key.in_port
                enforce_key = FlowKey(
                    dpid=int(ingress),
                    in_port=int(ingress_port) if ingress_port else key.in_port,
                    eth_src=key.eth_src,
                    eth_dst=key.eth_dst,
                    ip_src=key.ip_src,
                    ip_dst=key.ip_dst,
                    tp_dst=key.tp_dst
                )
                app.logger.info(f"{Color.GREEN}UNBLOCK FLOW (cooldown){Color.RESET} {enforce_key}")
                self.enforcer.enqueue(Action(ActionType.UNBLOCK, enforce_key))
                alarm_on = False
                counter = 0

        self.ds.set_flow_alarm_state(key, counter, alarm_on)

    # ============================================================
    #   SEZIONE 6 — Rilevamento DDoS Aggregato
    #  Analizza i flussi multipli verso la stessa destinazione:
    #   - Somma i bit rate totali per MAC di destinazione
    #   - Conta le sorgenti e i datapath unici
    #   - Se la condizione è sostenuta per SUSTAIN_K cicli
    #     e supera la soglia BH_BPS_THR → attiva BLACKHOLE
    # ============================================================

    def _detect_ddos_aggregate(self):
        app = self.enforcer.app
        BH_BPS_THR = float(self.cfg.get("ddos_dst_threshold_bps", 25_000_000))
        MIN_UNIQUE_SOURCES = int(self.cfg.get("ddos_min_flows", 3))
        MIN_UNIQUE_DPIDS = 2
        SUSTAIN_K = 3
        cooldown = float(self.cfg.get("ddos_cooldown_s", 10.0))
        micro = float(self.cfg.get("micro_threshold_bps", 200_000))

        total_bps_per_dst = defaultdict(float)
        unique_sources = defaultdict(set)
        unique_dpids = defaultdict(set)
        seen_pairs = set()

        # Aggrega throughput per destinazione
        for k in self.ds.get_all_flow_keys():
            last = self.ds.get_last_flow_delta(k)
            if not last or last.bps <= micro:
                continue
            pair = (k.eth_src, k.eth_dst)
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            total_bps_per_dst[k.eth_dst] += float(last.bps)
            unique_sources[k.eth_dst].add(k.eth_src)
            unique_dpids[k.eth_dst].add(k.dpid)

        # Valuta condizioni di superamento soglia
        now = time.time()
        for dst, tot_bps in total_bps_per_dst.items():
            exceeds = (tot_bps > BH_BPS_THR and
                       len(unique_sources[dst]) >= MIN_UNIQUE_SOURCES and
                       len(unique_dpids[dst]) >= MIN_UNIQUE_DPIDS)

            st = app.blackhole_state[dst]
            st["exceed"].append(exceeds)
            gate_key = ('dst', dst)

            if (now - self._last_ddos_block_ts.get(gate_key, 0)) < cooldown:
                continue
            if st["active"]:
                continue

            sustained = (len(st["exceed"]) == SUSTAIN_K and all(st["exceed"]))
            if sustained:
                duration_s = int(self.cfg.get("blackhole_duration_s", 20))
                app.logger.warning(
                    f"{Color.RED}[DDoS] BLACKHOLE{Color.RESET} dst={dst} total_bps={int(tot_bps)} "
                    f"sources={len(unique_sources[dst])} dpids={len(unique_dpids[dst])} for {duration_s}s"
                )
                self.enforcer.enqueue(Action(
                    kind=ActionType.BLACKHOLE,
                    key=PortKey(dpid=0, port_no=0),
                    params={"victim_mac": dst, "victim_ip": None, "duration_s": duration_s}
                ))
                st["active"] = True
                st["until"] = now + duration_s
                self._last_ddos_block_ts[gate_key] = now

        # Ripristino automatico dopo scadenza blackhole
        for dst, st in app.blackhole_state.items():
            if st["active"] and time.time() > st.get("until", 0):
                st["active"] = False
                st["exceed"].clear()
                app.logger.info(
                    f"{Color.GREEN}[UNBLACKHOLE]{Color.RESET} dst={dst} expired after cooldown"
                )

# ============================================================
#   FINE DEL MODULO POLICY
#  Il motore di policy agisce come cuore decisionale di SDN Defender:
#  raccoglie le metriche dal DataStore, adatta soglie e reagisce con
#  azioni mirate (LIMIT/BLOCK/UNBLOCK/BLACKHOLE) per contenere
#  comportamenti anomali in tempo reale.
# ============================================================
