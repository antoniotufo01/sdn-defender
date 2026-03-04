# sdn_defender/enforcement.py
# ============================================================
#   MODULO ENFORCEMENT
#  Responsabile dell’applicazione effettiva delle decisioni
#  del PolicyEngine sul piano dati (OpenFlow).
#  - Gestisce FlowMod per BLOCK / UNBLOCK / LIMIT / BLACKHOLE
#  - Garantisce idempotenza e coerenza tra i datapath
#  - Supporta azioni a livello di porta e di flusso
# ============================================================

from collections import deque
from typing import Deque, Set, Tuple, Optional

from .models import Action, ActionType, PortKey, FlowKey


class Enforcer:
    """
    Applica le azioni (FlowMod) in modo idempotente.
    Supporta:
      - BLOCK/UNBLOCK su porta o flusso
      - LIMIT (meter) su flusso
      - BLACKHOLE: drop temporaneo verso una destinazione (MAC o IP) su tutti gli switch
    """

    # ============================================================
    #   SEZIONE 1 — Inizializzazione
    #  Mantiene code di azioni da eseguire e insiemi di stato:
    #  - porte viste
    #  - porte bloccate
    #  - flussi bloccati
    # ============================================================

    def __init__(self, app, datastore, cfg):
        self.app = app
        self.ds = datastore
        self.cfg = cfg
        self._queue: Deque[Action] = deque()

        self._blocked: Set[Tuple[int, int]] = set()      # (dpid, port)
        self._seen_ports: Set[Tuple[int, int]] = set()   # porte già monitorate
        self._blocked_flows: Set[FlowKey] = set()        # flussi bloccati

    # ============================================================
    #   SEZIONE 2 — Utility
    #  Funzioni di supporto per registrare e interrogare lo stato
    #  delle porte osservate.
    # ============================================================

    def known_ports(self) -> Set[PortKey]:
        """Restituisce tutte le porte note al sistema."""
        return {PortKey(dpid, port) for (dpid, port) in self._seen_ports}

    def mark_seen_port(self, key: PortKey) -> None:
        """Segna una porta come 'vista' dal monitor."""
        self._seen_ports.add((key.dpid, key.port_no))

    # ============================================================
    #   SEZIONE 3 — Gestione coda di azioni
    #  enqueue(): aggiunge una nuova azione
    #  _drain(): esegue in ordine FIFO tutte le azioni in coda
    # ============================================================

    def enqueue(self, action: Action) -> None:
        """Accoda un'azione e attiva l'elaborazione immediata."""
        self._queue.append(action)
        self._drain()

    def _drain(self) -> None:
        """Esegue le azioni accodate, distinguendo tra porta e flusso."""
        while self._queue:
            a = self._queue.popleft()

            # --- Azione su FLUSSO ---
            if isinstance(a.key, FlowKey):
                if a.kind == ActionType.BLOCK:
                    self._block_flow(a.key)
                elif a.kind == ActionType.UNBLOCK:
                    self._unblock_flow(a.key)
                elif a.kind == ActionType.LIMIT:
                    rate = a.params.get("rate_kbps", 1000) if a.params else 1000
                    self._limit_flow(a.key, rate)
                elif a.kind == ActionType.BLACKHOLE:
                    # Il blackhole usa parametri specifici (vittima e durata)
                    self._blackhole_dest(
                        victim_mac=(a.params or {}).get("victim_mac"),
                        victim_ip=(a.params or {}).get("victim_ip"),
                        duration_s=int((a.params or {}).get(
                            "duration_s", self.cfg.get("blackhole_duration_s", 20)
                        )),
                    )
                continue

            # --- Azione su PORTA ---
            if isinstance(a.key, PortKey):
                if a.kind == ActionType.BLOCK:
                    self._block_port(a.key)
                elif a.kind == ActionType.UNBLOCK:
                    self._unblock_port(a.key)
                elif a.kind == ActionType.BLACKHOLE:
                    self._blackhole_dest(
                        victim_mac=(a.params or {}).get("victim_mac"),
                        victim_ip=(a.params or {}).get("victim_ip"),
                        duration_s=int((a.params or {}).get(
                            "duration_s", self.cfg.get("blackhole_duration_s", 20)
                        )),
                    )

    # ============================================================
    #   SEZIONE 4 — Gestione PORT BLOCK / UNBLOCK
    #  Installa o rimuove regole di DROP a livello di porta.
    # ============================================================

    def _block_port(self, key: PortKey) -> None:
        """Installa una regola di DROP sulla porta specificata."""
        dp = self.app.datapaths.get(key.dpid)
        if not dp:
            return
        if (key.dpid, key.port_no) in self._blocked:
            return  # già bloccata

        ofp = dp.ofproto
        parser = dp.ofproto_parser
        match = parser.OFPMatch(in_port=key.port_no)
        inst = []  # DROP

        mod = parser.OFPFlowMod(
            datapath=dp,
            priority=self.cfg["drop_priority"],
            match=match,
            instructions=inst,
            command=ofp.OFPFC_ADD,
            out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY,
            idle_timeout=0,
            hard_timeout=0,
        )
        dp.send_msg(mod)
        self.app.logger.info(f"Installing DROP on dpid={key.dpid}, port={key.port_no}")
        self._blocked.add((key.dpid, key.port_no))

    def _unblock_port(self, key: PortKey) -> None:
        """Rimuove la regola di DROP dalla porta specificata."""
        dp = self.app.datapaths.get(key.dpid)
        if not dp:
            return

        ofp = dp.ofproto
        parser = dp.ofproto_parser
        match = parser.OFPMatch(in_port=key.port_no)
        mod = parser.OFPFlowMod(
            datapath=dp,
            priority=self.cfg["drop_priority"],
            match=match,
            command=ofp.OFPFC_DELETE,
            out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY,
        )
        dp.send_msg(mod)
        self.app.logger.info(f"Removing DROP on dpid={key.dpid}, port={key.port_no}")
        self._blocked.discard((key.dpid, key.port_no))

    # ============================================================
    #   SEZIONE 5 — Gestione BLOCK / UNBLOCK per FLUSSI
    #  Installa o rimuove regole DROP specifiche per flusso.
    # ============================================================

    def _build_flow_match(self, dp, key: FlowKey):
        """Crea un match OpenFlow coerente con i campi del FlowKey."""
        parser = dp.ofproto_parser
        m = {"in_port": key.in_port}
        if key.eth_src:
            m["eth_src"] = key.eth_src
        if key.eth_dst:
            m["eth_dst"] = key.eth_dst
        if key.ip_src or key.ip_dst:
            m["eth_type"] = 0x0800
            if key.ip_src:
                m["ipv4_src"] = key.ip_src
            if key.ip_dst:
                m["ipv4_dst"] = key.ip_dst
        return parser.OFPMatch(**m)

    def _block_flow(self, key: FlowKey) -> None:
        """Installa una regola di DROP per un flusso specifico."""
        dp = self.app.datapaths.get(key.dpid)
        if not dp or key in self._blocked_flows:
            return
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        match = self._build_flow_match(dp, key)
        mod = parser.OFPFlowMod(
            datapath=dp,
            priority=self.cfg["drop_priority"],
            match=match,
            instructions=[],  # DROP
            command=ofp.OFPFC_ADD,
            out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY,
            idle_timeout=0,
            hard_timeout=0,
        )
        dp.send_msg(mod)
        self._blocked_flows.add(key)
        self.app.logger.info(f"Installing DROP (flow) {key}")

    def _unblock_flow(self, key: FlowKey) -> None:
        """Rimuove la regola di DROP per un flusso specifico."""
        dp = self.app.datapaths.get(key.dpid)
        if not dp:
            return
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        match = self._build_flow_match(dp, key)
        mod = parser.OFPFlowMod(
            datapath=dp,
            priority=self.cfg["drop_priority"],
            match=match,
            command=ofp.OFPFC_DELETE,
            out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY,
        )
        dp.send_msg(mod)
        self._blocked_flows.discard(key)
        self.app.logger.info(f"Removing DROP (flow) {key}")

    # ============================================================
    #   SEZIONE 6 — RATE LIMITING (Meter)
    #  Installa un meter per limitare la banda di un flusso.
    #  Usa meter_id=1 come demo, con banda drop sopra soglia.
    # ============================================================

    def _limit_flow(self, key: FlowKey, rate_kbps: int) -> None:
        """Installa un meter per limitare la banda di un flusso."""
        dp = self.app.datapaths.get(key.dpid)
        if not dp:
            return
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        match = self._build_flow_match(dp, key)

        # Crea/aggiorna un meter id=1 (demo)
        meter_mod = parser.OFPMeterMod(
            datapath=dp,
            command=ofp.OFPMC_ADD,
            flags=ofp.OFPMF_KBPS,
            meter_id=1,
            bands=[parser.OFPMeterBandDrop(rate=rate_kbps)]
        )
        dp.send_msg(meter_mod)

        inst = [
            parser.OFPInstructionMeter(meter_id=1),
            parser.OFPInstructionActions(
                ofp.OFPIT_APPLY_ACTIONS,
                [parser.OFPActionOutput(ofp.OFPP_NORMAL)]
            )
        ]
        mod = parser.OFPFlowMod(
            datapath=dp,
            priority=self.cfg["drop_priority"],
            match=match,
            instructions=inst,
            command=ofp.OFPFC_ADD,
            out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY,
            idle_timeout=0,
            hard_timeout=0,
        )
        dp.send_msg(mod)
        self.app.logger.info(f"Installing LIMIT {rate_kbps} kbps on flow {key}")

    # ============================================================
    #   SEZIONE 7 — BLACKHOLE (Mitigazione DDoS)
    #  Installa regole di DROP su tutte le destinazioni (MAC/IP)
    #  per durata temporanea, con auto-rimozione (hard_timeout).
    # ============================================================

    def _blackhole_dest(self, victim_mac: Optional[str], victim_ip: Optional[str], duration_s: int) -> None:
        """
        Installa su TUTTI i datapath una regola di DROP che matcha la destinazione (MAC o IP).
        Usa hard_timeout=duration_s per rimuoversi automaticamente.
        """
        if not victim_mac and not victim_ip:
            self.app.logger.warning("BLACKHOLE requested without victim_mac or victim_ip")
            return

        for dpid, dp in self.app.datapaths.items():
            ofp = dp.ofproto
            parser = dp.ofproto_parser

            match_kwargs = {}
            if victim_ip:
                match_kwargs["eth_type"] = 0x0800
                match_kwargs["ipv4_dst"] = victim_ip
            elif victim_mac:
                match_kwargs["eth_dst"] = victim_mac

            match = parser.OFPMatch(**match_kwargs)

            mod = parser.OFPFlowMod(
                datapath=dp,
                priority=self.cfg["drop_priority"] + 5,
                match=match,
                instructions=[],       # DROP
                command=ofp.OFPFC_ADD,
                out_port=ofp.OFPP_ANY,
                out_group=ofp.OFPG_ANY,
                idle_timeout=0,
                hard_timeout=int(duration_s),
                flags=ofp.OFPFF_SEND_FLOW_REM,
            )
            dp.send_msg(mod)
            self.app.logger.info(
                f"Installing BLACKHOLE on dpid={dpid} dst="
                f"{victim_ip if victim_ip else victim_mac} "
                f"for {int(duration_s)}s"
            )

# ============================================================
#   FINE DEL MODULO ENFORCEMENT
#  L’Enforcer è il braccio operativo del SDN Defender:
#  traduce le decisioni della Policy in regole OpenFlow,
#  applicandole in modo sicuro, coerente e temporizzato.
# ============================================================
