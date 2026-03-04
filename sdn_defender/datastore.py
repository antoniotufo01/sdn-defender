# sdn_defender/datastore.py
# ============================================================
#   MODULO DATASTORE
#  Gestisce lo stato condiviso e thread-safe tra i moduli del sistema:
#   - Serie temporali delle statistiche di porte e flussi
#   - Stato degli allarmi (counter e flag on/off)
#   - Soglie dinamiche EWMA per adattamento automatico
#   - Liste esterne (whitelist MAC e blocklist FLUSSI)
# ============================================================

import threading
from collections import defaultdict, deque
from typing import Deque, Dict, Iterable, Tuple, List, Set

from .models import PortKey, PortDelta, FlowKey, FlowDelta


class DataStore:

    # ============================================================
    #   SEZIONE 1 — Inizializzazione
    #  Crea tutte le strutture dati interne (deque e dict) e
    #  il lock per garantire accesso thread-safe da Monitor e Policy.
    # ============================================================

    def __init__(self, window_s: int, cfg=None):
        self._lock = threading.Lock()
        self.cfg = cfg or {}

        # --- Serie temporali e allarmi per PORTE ---
        self._port_series: Dict[PortKey, Deque[PortDelta]] = defaultdict(deque)
        self._alarm_counter: Dict[PortKey, int] = defaultdict(int)
        self._alarm_on: Dict[PortKey, bool] = defaultdict(bool)

        # --- Serie temporali e allarmi per FLUSSI ---
        self._flow_series: Dict[FlowKey, Deque[FlowDelta]] = defaultdict(deque)
        self._flow_alarm_counter: Dict[FlowKey, int] = defaultdict(int)
        self._flow_alarm_on: Dict[FlowKey, bool] = defaultdict(bool)

        # --- Input esterno (API / moduli) ---
        self._ext_whitelist_macs: Set[str] = set()   # MAC da non bloccare mai
        self._ext_block_flows: Set[FlowKey] = set()  # Flussi forzati in DROP

        # --- Finestra temporale in secondi ---
        self._window_s = window_s

        # --- Soglie dinamiche EWMA ---
        self._dynamic_thresholds: Dict[PortKey, float] = defaultdict(lambda: 0.0)      # per porta
        self._dynamic_flow_thresholds: Dict[FlowKey, float] = defaultdict(lambda: 0.0) # per flusso

    # ============================================================
    #   SEZIONE 2 — Serie temporali (PORTE)
    #  Mantiene i valori bps/pps derivati dalle statistiche cumulative.
    #  La finestra temporale è limitata da window_s.
    # ============================================================

    def update_port_delta(self, d: PortDelta) -> None:
        with self._lock:
            dq = self._port_series[d.key]
            dq.append(d)
            while dq and (d.ts - dq[0].ts) > self._window_s:
                dq.popleft()

    def get_last_port_delta(self, key: PortKey) -> PortDelta | None:
        with self._lock:
            dq = self._port_series.get(key)
            if not dq:
                return None
            return dq[-1]

    def get_all_port_keys(self) -> Iterable[PortKey]:
        with self._lock:
            return list(self._port_series.keys())

    # ============================================================
    #   SEZIONE 3 — Stato Alarm (PORTE)
    #  Ogni porta ha un contatore di superamenti soglia e un flag
    #  che indica se l’allarme è attivo (on/off).
    # ============================================================

    def get_alarm_state(self, key: PortKey) -> Tuple[int, bool]:
        with self._lock:
            return self._alarm_counter[key], self._alarm_on[key]

    def set_alarm_state(self, key: PortKey, counter: int, on: bool) -> None:
        with self._lock:
            self._alarm_counter[key] = counter
            self._alarm_on[key] = on

    # ============================================================
    #   SEZIONE 4 — Serie temporali (FLUSSI)
    #  Analogo alle porte, ma con chiave (dpid, in_port, eth_src, eth_dst).
    # ============================================================

    def update_flow_delta(self, d: FlowDelta) -> None:
        with self._lock:
            dq = self._flow_series[d.key]
            dq.append(d)
            while dq and (d.ts - dq[0].ts) > self._window_s:
                dq.popleft()

    def get_last_flow_delta(self, key: FlowKey) -> FlowDelta | None:
        with self._lock:
            dq = self._flow_series.get(key)
            if not dq:
                return None
            return dq[-1]

    def get_all_flow_keys(self) -> Iterable[FlowKey]:
        with self._lock:
            return list(self._flow_series.keys())

    # ============================================================
    #   SEZIONE 5 — Stato Alarm (FLUSSI)
    #  Gestisce i contatori e gli stati on/off per i flussi monitorati.
    # ============================================================

    def get_flow_alarm_state(self, key: FlowKey) -> Tuple[int, bool]:
        with self._lock:
            return self._flow_alarm_counter[key], self._flow_alarm_on[key]

    def set_flow_alarm_state(self, key: FlowKey, counter: int, on: bool) -> None:
        with self._lock:
            self._flow_alarm_counter[key] = counter
            self._flow_alarm_on[key] = on

    # ============================================================
    #   SEZIONE 6 — Input Esterno: Whitelist MAC
    #  Lista di MAC che non devono mai essere bloccati.
    #  Utilizzata dalle API REST e dal PolicyEngine.
    # ============================================================

    def add_whitelist_mac(self, mac: str) -> None:
        with self._lock:
            if mac:
                self._ext_whitelist_macs.add(mac.lower())

    def remove_whitelist_mac(self, mac: str) -> None:
        with self._lock:
            if mac:
                self._ext_whitelist_macs.discard(mac.lower())

    def list_whitelist_macs(self) -> List[str]:
        with self._lock:
            return sorted(self._ext_whitelist_macs)

    def is_mac_whitelisted(self, mac: str) -> bool:
        with self._lock:
            return mac.lower() in self._ext_whitelist_macs if mac else False

    # ============================================================
    #   SEZIONE 7 — Input Esterno: Blocklist FLUSSI
    #  Mantiene i flussi forzatamente bloccati tramite API.
    # ============================================================

    def add_block_flow(self, fk: FlowKey) -> None:
        with self._lock:
            self._ext_block_flows.add(fk)

    def remove_block_flow(self, fk: FlowKey) -> None:
        with self._lock:
            self._ext_block_flows.discard(fk)

    def list_block_flows(self) -> Iterable[FlowKey]:
        with self._lock:
            return list(self._ext_block_flows)

    def external_block_flows(self) -> Set[FlowKey]:
        with self._lock:
            return set(self._ext_block_flows)

    def get_flow_series(self, key: FlowKey):
        """Restituisce la lista di campioni (bps/pps) per un flusso."""
        with self._lock:
            dq = self._flow_series.get(key)
            return list(dq) if dq else []

    # ============================================================
    #   SEZIONE 8 — Soglie Dinamiche (PORTE)
    #  Aggiorna e restituisce soglie EWMA (media mobile esponenziale)
    #  per adattare dinamicamente il comportamento della policy.
    # ============================================================

    def update_dynamic_threshold(self, key: PortKey, value: float, alpha: float = 0.3):
        with self._lock:
            prev = self._dynamic_thresholds[key]
            ewma = value if prev == 0 else alpha * value + (1 - alpha) * prev
            self._dynamic_thresholds[key] = ewma

    def get_dynamic_threshold(self, key: PortKey) -> float:
        with self._lock:
            return self._dynamic_thresholds.get(key, 0.0)

    # ============================================================
    #   SEZIONE 9 — Soglie Dinamiche (FLUSSI)
    #  Applica un filtro EWMA più lento e vincola la soglia
    #  entro 0 e 3× la soglia statica, per evitare falsi positivi.
    # ============================================================

    def update_dynamic_flow_threshold(self, key: FlowKey, value: float, alpha: float = 0.1):
        """
        Aggiorna la soglia dinamica per flusso con un filtro EWMA più "lento"
        (alpha ridotto) e applica limiti di sicurezza:
        - scarta valori negativi (reset contatori o overflow)
        - mantiene la soglia tra 0 e 3× la soglia statica
        """
        with self._lock:
            prev = self._dynamic_flow_thresholds[key]

            # 🔹 Evita input negativi dovuti a reset contatori
            if value < 0:
                value = 0.0

            # 🔹 Calcolo EWMA
            ewma = value if prev == 0 else alpha * value + (1 - alpha) * prev

            # 🔹 Recupera soglia statica come riferimento
            try:
                base_thr = float(self.cfg.get("threshold_bps", 2_000_000))
            except AttributeError:
                base_thr = 2_000_000

            # 🔹 Impone limiti di sicurezza
            max_allowed = 3 * base_thr
            ewma = max(0.0, min(ewma, max_allowed))

            self._dynamic_flow_thresholds[key] = ewma

    def get_dynamic_flow_threshold(self, key: FlowKey) -> float:
        with self._lock:
            return self._dynamic_flow_thresholds.get(key, 0.0)

# ============================================================
#   FINE DEL MODULO DATASTORE
#  Il DataStore è il repository centrale dello stato runtime:
#  sincronizza le metriche tra Monitor, Policy ed Enforcer e
#  garantisce coerenza tramite accesso thread-safe.
# ============================================================
