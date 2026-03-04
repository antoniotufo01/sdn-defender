# sdn_defender/controller_app.py
# ============================================================
#   MODULO CONTROLLER PRINCIPALE (SDNDefender)
#  Gestisce:
#   - Registrazione e stato dei datapath OpenFlow
#   - Monitoraggio delle statistiche tramite Monitor
#   - Enforcement di policy tramite Enforcer
#   - Decisioni dinamiche di sicurezza tramite PolicyEngine
#   - API REST per gestione whitelist e blocklist
#  Struttura "thin controller" → la logica principale è delegata ai moduli.
# ============================================================

import json
import time
import threading
import logging

from collections import defaultdict, deque
from webob import Response
from ryu.app.wsgi import ControllerBase, route, WSGIApplication

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    MAIN_DISPATCHER, CONFIG_DISPATCHER, HANDSHAKE_DISPATCHER, DEAD_DISPATCHER,
    set_ev_cls
)
from ryu.controller.ofp_event import EventOFPStateChange
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet
from ryu.lib import hub

from .monitor import Monitor
from .policy import PolicyEngine
from .enforcement import Enforcer
from .datastore import DataStore
from .config import CFG
from .models import FlowKey, Action, ActionType

API_BASE = '/policy'

# --- Silenzia log HTTP del server WSGI interno di Ryu ---
logging.getLogger('ryu.app.wsgi').setLevel(logging.WARNING)

class Color:
    RESET = "\033[0m"
    GREEN = "\033[92m"


# ============================================================
#   CLASSE PRINCIPALE: SDNDefender
#  Implementa il controller SDN principale.
#  Coordina monitoraggio, policy ed enforcement in tempo reale.
# ============================================================

class SDNDefender(app_manager.RyuApp):

    _CONTEXTS = {'wsgi': WSGIApplication}
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # === Parametri di robustezza per il rilevamento DDoS ===
    BH_BPS_THR = 25_000_000        # soglia blackhole (≈200 Mbps)
    MIN_UNIQUE_SOURCES = 3
    MIN_UNIQUE_DPIDS = 2
    SUSTAIN_K = 3
    WARMUP_SAMPLES = 5

    # ============================================================
    #   SEZIONE 1 — Inizializzazione del Controller
    #  Costruisce i moduli core (Monitor, Enforcer, PolicyEngine)
    #  e avvia thread secondari di monitoraggio e logging.
    # ============================================================

    def __init__(self, *args, **kwargs):
        super(SDNDefender, self).__init__(*args, **kwargs)
        self.datapaths: dict[int, object] = {}
        self.interval_id = 0

        # --- Moduli interni ---
        self.ds = DataStore(CFG["stats_window_s"], CFG)
        self.enforcer = Enforcer(self, self.ds, CFG)
        self.monitor = Monitor(self, self.ds, CFG)
        self.policy = PolicyEngine(self.ds, self.enforcer, CFG)

        # --- Stato MAC-to-port (Learning Switch) ---
        self.mac_to_port = defaultdict(dict)

        # --- Tabelle di tracking ingress e stato blackhole ---
        self.ingress_table = {}  # eth_src → (dpid, in_port)
        self.blackhole_state = defaultdict(lambda: {
            "active": False, "until": 0.0, "exceed": deque(maxlen=self.SUSTAIN_K)
        })

        # --- Avvio dei thread principali ---
        self.monitor.start()
        self.policy.start()

        # --- Thread periodico di logging (diagnostico) ---
        threading.Thread(target=self._periodic_status_logger, daemon=True).start()

        # --- Registrazione delle API REST (se abilitate da config) ---
        self.cfg = CFG
        if self.cfg.get("enable_rest_api", False):
            wsgi = kwargs['wsgi']
            wsgi.register(PolicyRestApi, {'sdndefender_app': self})

    # ============================================================
    #   SEZIONE 2 — Logger periodico di stato
    #  Stampa periodicamente i flussi attivi e le soglie dinamiche
    #  per debugging e validazione del comportamento.
    # ============================================================

    def _periodic_status_logger(self):
        interval = 5
        while True:
            time.sleep(interval)
            print("\n===== STATUS LOG =====")

            # --- Porte (disabilitato per semplicità, attivabile se serve) ---
            #for key in self.ds.get_all_port_keys():
            #    last = self.ds.get_last_port_delta(key)
            #    dyn_thr = self.ds.get_dynamic_threshold(key)
            #    if last:
            #        print(f"[PORT] dpid={key.dpid}, port={key.port_no}, "
            #              f"rx={last.rx_bps:.1f} B/s, tx={last.tx_bps:.1f} B/s, "
            #              f"dyn_thr={(dyn_thr or 0):.1f}")

            # --- Flussi (monitoraggio attivo) ---
            for key in self.ds.get_all_flow_keys():
                last = self.ds.get_last_flow_delta(key)
                dyn_thr = self.ds.get_dynamic_flow_threshold(key)
                if last:
                    print(f"[FLOW] dpid={key.dpid}, in_port={key.in_port}, "
                          f"src={key.eth_src}, dst={key.eth_dst}, "
                          f"rate={last.bps:.1f} B/s, dyn_thr={(dyn_thr or 0):.1f}")

            print("======================\n")

    # ============================================================
    #   SEZIONE 3 — Gestione dei DATAPATH (switch)
    #  Registra o rimuove switch in base agli eventi Ryu.
    # ============================================================

    @set_ev_cls(EventOFPStateChange, [MAIN_DISPATCHER, HANDSHAKE_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if dp.id not in self.datapaths:
                self.logger.info("Register datapath: %016x", dp.id)
                self.datapaths[dp.id] = dp
        elif ev.state == DEAD_DISPATCHER:
            if dp.id in self.datapaths:
                self.logger.info("Unregister datapath: %016x", dp.id)
                del self.datapaths[dp.id]

    # ============================================================
    #   SEZIONE 4 — Setup base (Table-Miss)
    #  Installa la regola table-miss per inviare i pacchetti
    #  sconosciuti al controller, garantendo visibilità completa.
    # ============================================================

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=dp, priority=CFG["table_miss_priority"],
            match=match, instructions=inst
        )
        dp.send_msg(mod)

    # ============================================================
    #   SEZIONE 5 — Learning Switch Minimale
    #  Mantiene la tabella MAC→Port per instradare frame noti
    #  e genera flow rules temporanee per ridurre overhead.
    # ============================================================

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(data=msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return
        dst = eth.dst
        src = eth.src

        dpid = dp.id
        self.mac_to_port[dpid][src] = in_port
        self.update_ingress(dpid, src, dst)

        # Determina la porta di uscita
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofp.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Installa regola di forwarding per traffico noto
        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(datapath=dp, priority=1, match=match, instructions=inst)
            dp.send_msg(mod)

        # Inoltra pacchetto al destinatario
        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=None if msg.buffer_id != ofp.OFP_NO_BUFFER else msg.data
        )
        dp.send_msg(out)

    # ============================================================
    #   SEZIONE 6 — Gestione Statistiche
    #  Riceve le risposte alle richieste di PortStats/FlowStats
    #  e le inoltra al modulo Monitor per l’analisi.
    # ============================================================

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        dp = ev.msg.datapath
        self.monitor.on_port_stats_reply(dp.id, ev.msg.body)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        dp = ev.msg.datapath
        self.monitor.on_flow_stats_reply(dp.id, ev.msg.body)

    # ============================================================
    #   SEZIONE 7 — Gestione rimozione Flow (FlowRemoved)
    #  Log automatico della rimozione di regole temporanee o
    #  flussi in blackhole.
    # ============================================================

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def _flow_removed_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        m = msg.match

        victim_mac = m.get("eth_dst", None)
        victim_ip = m.get("ipv4_dst", None)

        if victim_mac or victim_ip:
            self.logger.info(
                f"{Color.GREEN}[DDoS] BLACKHOLE REMOVED {Color.RESET} on dpid={dp.id}, "
                f"dst={victim_ip if victim_ip else victim_mac}, "
                f"dur={msg.duration_sec + msg.duration_nsec/1e9:.1f}s, "
                f"pkts={msg.packet_count}, bytes={msg.byte_count}"
            )
        else:
            self.logger.info(
                "AUTO-UNBLOCK (FlowRemoved) dpid=%s match=%s reason=%s dur=%.1fs pkts=%s bytes=%s",
                dp.id, m, msg.reason,
                msg.duration_sec + msg.duration_nsec/1e9,
                msg.packet_count, msg.byte_count
            )

    # ============================================================
    #   SEZIONE 8 — Helper per Ingress e Topologia
    #  Mantiene la mappa sorgente → (switch, porta) per
    #  applicare le policy solo sul punto di ingresso corretto.
    # ============================================================

    def update_ingress(self, dpid, eth_src, eth_dst):
        """Aggiorna la tabella di ingresso per l’host sorgente."""
        if eth_src not in self.ingress_table:
            in_port = self.mac_to_port[dpid].get(eth_src)
            self.ingress_table[eth_src] = (dpid, in_port)

    def get_ingress(self, eth_src, eth_dst):
        """Restituisce il DPID di ingresso associato all’host sorgente."""
        entry = self.ingress_table.get(eth_src)
        return entry[0] if entry else None

    def find_ingress_by_mac(self, eth_src, eth_dst):
        """Ricerca nelle tabelle mac_to_port e restituisce (dpid, in_port)."""
        if not eth_src:
            return None, None
        for dpid, mtab in self.mac_to_port.items():
            try:
                if eth_src in mtab:
                    return dpid, mtab[eth_src]
            except Exception:
                continue
        return None, None


# ============================================================
#   SEZIONE 9 — API REST (PolicyRestApi)
#  Espone endpoint REST per:
#   - Consultare e aggiornare la whitelist dei MAC
#   - Consultare, aggiungere o rimuovere flussi bloccati
# ============================================================

class PolicyRestApi(ControllerBase):
    def __init__(self, req, link, data, **config):
        super().__init__(req, link, data, **config)
        self.app = data['sdndefender_app']

    # --- Log colorato per richieste REST ---
    def log_api(self, action: str, detail: str):
        color = {
            "ADD": Color.GREEN,
            "DEL": "\033[91m",
            "GET": "\033[96m"
        }.get(action.upper(), Color.RESET)
        self.app.logger.info(f"{color}[API {action.upper()}]{Color.RESET} {detail}")

    # --- WHITELIST MACs ---
    @route('sdndefender', API_BASE + '/whitelist', methods=['GET'])
    def get_whitelist(self, req, **kwargs):
        wl_cfg = self.app.cfg.get('whitelist_macs', [])
        wl_ext = self.app.ds.list_whitelist_macs()
        body = json.dumps({"config": wl_cfg, "external": wl_ext}).encode()
        return Response(status=200, content_type='application/json', body=body)

    @route('sdndefender', API_BASE + '/whitelist', methods=['POST'])
    def add_whitelist(self, req, **kwargs):
        try:
            j = req.json_body
            self.log_api("ADD", f"Whitelist MAC {j.get('mac')}")
            mac = j.get('mac')
            if not mac:
                return Response(status=400, body=b'{"error":"missing mac"}')
            self.app.ds.add_whitelist_mac(mac)
            return Response(status=200, body=b'{"ok":true}')
        except Exception as e:
            return Response(status=400, body=str(e).encode())

    @route('sdndefender', API_BASE + '/whitelist', methods=['DELETE'])
    def remove_whitelist(self, req, **kwargs):
        try:
            j = req.json_body
            self.log_api("DEL", f"Whitelist MAC {j.get('mac')}")
            mac = j.get('mac')
            if not mac:
                return Response(status=400, body=b'{"error":"missing mac"}')
            self.app.ds.remove_whitelist_mac(mac)
            return Response(status=200, body=b'{"ok":true}')
        except Exception as e:
            return Response(status=400, body=str(e).encode())

    # --- BLOCKLIST FLOWS ---
    @route('sdndefender', API_BASE + '/blockflows', methods=['GET'])
    def get_blockflows(self, req, **kwargs):
        flows = [fk.__dict__ for fk in self.app.ds.list_block_flows()]
        return Response(status=200, content_type='application/json',
                        body=json.dumps(flows).encode())

    @route('sdndefender', API_BASE + '/blockflows', methods=['POST'])
    def add_blockflow(self, req, **kwargs):
        try:
            j = req.json_body
            self.log_api(
                "ADD",
                f"Block flow {j.get('eth_src')} → {j.get('eth_dst')} "
                f"(dpid={j.get('dpid')}, in_port={j.get('in_port')})"
            )
            dpid = int(j['dpid'])
            in_port = int(j['in_port'])
            eth_src = j['eth_src']
            eth_dst = j['eth_dst']
            fk = FlowKey(dpid=dpid, in_port=in_port,
                         eth_src=eth_src, eth_dst=eth_dst,
                         ip_src=None, ip_dst=None, tp_dst=None)
            self.app.ds.add_block_flow(fk)
            self.app.enforcer.enqueue(Action(ActionType.BLOCK, fk))
            return Response(status=200, body=b'{"ok":true}')
        except KeyError as e:
            return Response(status=400, body=f'{{"error":"missing {e.args[0]}"}}'.encode())
        except Exception as e:
            return Response(status=400, body=str(e).encode())

    @route('sdndefender', API_BASE + '/blockflows', methods=['DELETE'])
    def remove_blockflow(self, req, **kwargs):
        try:
            j = req.json_body
            self.log_api(
                "DEL",
                f"Unblock flow {j.get('eth_src')} → {j.get('eth_dst')} "
                f"(dpid={j.get('dpid')}, in_port={j.get('in_port')})"
            )
            dpid = int(j['dpid'])
            in_port = int(j['in_port'])
            eth_src = j['eth_src']
            eth_dst = j['eth_dst']
            fk = FlowKey(dpid=dpid, in_port=in_port,
                         eth_src=eth_src, eth_dst=eth_dst,
                         ip_src=None, ip_dst=None, tp_dst=None)
            self.app.ds.remove_block_flow(fk)
            self.app.enforcer.enqueue(Action(ActionType.UNBLOCK, fk))
            return Response(status=200, body=b'{"ok":true}')
        except KeyError as e:
            return Response(status=400, body=f'{{"error":"missing {e.args[0]}"}}'.encode())
        except Exception as e:
            return Response(status=400, body=str(e).encode())


# ============================================================
#   FINE DEL MODULO CONTROLLER
#  Il controller SDNDefender integra monitoraggio, policy e
#  enforcement per realizzare un sistema di difesa adattivo e
#  distribuito contro attacchi DoS/DDoS su rete SDN.
# ============================================================
