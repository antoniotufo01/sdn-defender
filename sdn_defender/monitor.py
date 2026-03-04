# sdn_defender/monitor.py
# ============================================================
#   MODULO MONITOR
#  Responsabile del monitoraggio periodico del traffico:
#   - Invia richieste OpenFlow di PortStats e FlowStats
#   - Calcola delta (bps/pps) dalle statistiche cumulative
#   - Pubblica i valori nel DataStore
#   - Non implementa logica di soglia → delegata al PolicyEngine
# ============================================================

import time
from operator import attrgetter

from ryu.lib import hub

from .models import PortKey, PortDelta, FlowKey, FlowDelta


class Monitor:

    # ============================================================
    #   SEZIONE 1 — Inizializzazione
    #  Configura riferimenti al controller, al datastore condiviso
    #  e crea strutture per memorizzare i valori precedenti
    #  (necessari al calcolo dei delta).
    # ============================================================

    def __init__(self, app, datastore, cfg):
        self.app = app
        self.ds = datastore
        self.cfg = cfg

        # Cache dei valori precedenti (per porte e flussi)
        self._prev = {}       # (dpid, port) -> (rx_pkts, rx_bytes, rx_err, tx_pkts, tx_bytes, tx_err)
        self._prev_flow = {}  # (dpid, in_port, eth_src, eth_dst) -> (pkts, bytes)
        self._thread = None

    # ============================================================
    #   SEZIONE 2 — Ciclo di vita
    #  Avvio del thread che ciclicamente invia richieste
    #  di statistiche ai datapath conosciuti.
    # ============================================================

    def start(self):
        """Avvia il thread principale del monitor."""
        self._thread = hub.spawn(self._loop)

    def _loop(self):
        """Loop principale di polling delle statistiche."""
        while True:
            # Invia richieste di statistiche a tutti i datapath attivi
            for dp in list(self.app.datapaths.values()):
                self._request_port_stats(dp)
                self._request_flow_stats(dp)
            # intervallo di polling configurabile
            hub.sleep(self.cfg["poll_interval_s"])

    # ============================================================
    #   SEZIONE 3 — Richieste OpenFlow
    #  Costruisce e invia messaggi di richiesta PortStats/FlowStats.
    # ============================================================

    def _request_port_stats(self, dp):
        """Invia richiesta di statistiche delle porte a uno switch."""
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        req = parser.OFPPortStatsRequest(dp, 0, ofp.OFPP_ANY)
        dp.send_msg(req)

    def _request_flow_stats(self, dp):
        """Invia richiesta di statistiche dei flussi a uno switch."""
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        req = parser.OFPFlowStatsRequest(dp, 0, ofp.OFPTT_ALL)
        dp.send_msg(req)

    # ============================================================
    #   SEZIONE 4 — Gestione risposte (callback)
    #  Queste funzioni vengono richiamate dagli handler del
    #  controller al ricevimento dei messaggi di risposta.
    # ============================================================

    def on_port_stats_reply(self, dpid, body, ts=None):
        """
        Elabora le statistiche di porta ricevute.
        Calcola i delta (bps/pps) e aggiorna il DataStore.
        """
        ts = ts or time.time()
        interval = float(self.cfg["poll_interval_s"])

        for stat in sorted(body, key=attrgetter('port_no')):
            key = (dpid, stat.port_no)

            # Prima misura → solo inizializzazione
            if key not in self._prev:
                self._prev[key] = (stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                                   stat.tx_packets, stat.tx_bytes, stat.tx_errors)
                # Registra la porta come "vista" (necessario per policy/enforcer)
                self.app.enforcer.mark_seen_port(PortKey(dpid, stat.port_no))
                continue

            # Calcolo delta tra due campioni successivi
            pr = self._prev[key]
            rx_bps = (stat.rx_bytes - pr[1]) * 8.0 / interval
            tx_bps = (stat.tx_bytes - pr[4]) * 8.0 / interval
            rx_pps = (stat.rx_packets - pr[0]) / interval
            tx_pps = (stat.tx_packets - pr[3]) / interval

            # Aggiornamento DataStore
            pkey = PortKey(dpid, stat.port_no)
            self.ds.update_port_delta(PortDelta(
                key=pkey, ts=ts,
                rx_bps=rx_bps, tx_bps=tx_bps,
                rx_pps=rx_pps, tx_pps=tx_pps
            ))

            # Segnala la porta come "vista"
            self.app.enforcer.mark_seen_port(pkey)

            # Aggiorna i valori precedenti
            self._prev[key] = (stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                               stat.tx_packets, stat.tx_bytes, stat.tx_errors)

    def on_flow_stats_reply(self, dpid, body, ts=None):
        """
        Elabora le statistiche di flusso ricevute.
        Calcola i delta (bps/pps) per ogni flusso L2 attivo.
        """
        ts = ts or time.time()
        interval = float(self.cfg["poll_interval_s"])

        drop_prio = self.cfg["drop_priority"]
        miss_prio = self.cfg["table_miss_priority"]

        for stat in body:
            # Ignora le regole di table-miss o DROP statiche
            if getattr(stat, "priority", 0) in (miss_prio,):
                continue
            if not getattr(stat, "instructions", None):
                continue

            # Estrae i campi principali del match (L2)
            m = stat.match
            in_port = m.get('in_port', None)
            eth_src = m.get('eth_src', None)
            eth_dst = m.get('eth_dst', None)

            if in_port is None or not eth_src or not eth_dst:
                continue

            # Chiave identificativa del flusso
            key = (dpid, in_port, eth_src, eth_dst)
            prev = self._prev_flow.get(key)

            # Prima misura → inizializzazione
            if prev is None:
                self._prev_flow[key] = (stat.packet_count, stat.byte_count)
                continue

            # Calcolo delta per pacchetti e byte
            pkts_prev, bytes_prev = prev
            pps = (stat.packet_count - pkts_prev) / interval
            bps = (stat.byte_count - bytes_prev) * 8.0 / interval

            # Aggiornamento DataStore con nuovo delta
            fk = FlowKey(dpid=dpid, in_port=in_port, eth_src=eth_src, eth_dst=eth_dst)
            self.ds.update_flow_delta(FlowDelta(key=fk, ts=ts, bps=bps, pps=pps))

            # Salva i nuovi contatori per il prossimo ciclo
            self._prev_flow[key] = (stat.packet_count, stat.byte_count)

# ============================================================
#   FINE DEL MODULO MONITOR
#  Il Monitor agisce come "osservatore passivo" del traffico,
#  raccogliendo misurazioni raw e aggiornando il DataStore.
#  Nessuna decisione viene presa qui: è compito del PolicyEngine.
# ============================================================
