# sdn_defender/models.py
# ============================================================
#   MODULO MODELS
#  Definisce tutte le strutture dati fondamentali (chiavi, misure
#  e azioni) utilizzate da Monitor, Policy e Enforcer.
#  - PortKey / FlowKey: identificatori univoci di porte e flussi
#  - PortDelta / FlowDelta: misure temporali derivate dalle stats
#  - ActionType / Action: tipi di azione e payload associato
# ============================================================

from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional, Union


# ============================================================
#   SEZIONE 1 — Chiavi di Identificazione
#  Le chiavi servono a rappresentare entità univoche nel sistema:
#  - PortKey: coppia (dpid, port_no)
#  - FlowKey: tuple estendibile per match MAC/IP
# ============================================================

@dataclass(frozen=True)
class PortKey:
    """Identifica in modo univoco una porta di uno switch."""
    dpid: int
    port_no: int


@dataclass(frozen=True)
class FlowKey:
    """Chiave di un flusso (match base su MAC, IP e porta)."""
    dpid: int
    in_port: int
    eth_src: Optional[str] = None
    eth_dst: Optional[str] = None
    ip_src: Optional[str] = None
    ip_dst: Optional[str] = None
    tp_dst: Optional[int] = None


# ============================================================
#   SEZIONE 2 — Misure derivate (Delta)
#  PortDelta e FlowDelta rappresentano i tassi per-secondo
#  calcolati dal modulo Monitor a partire dalle statistiche cumulative.
# ============================================================

@dataclass
class PortDelta:
    """Misure per-secondo derivate dalle statistiche cumulative delle porte."""
    key: PortKey
    ts: float
    rx_bps: float
    tx_bps: float
    rx_pps: float
    tx_pps: float


@dataclass
class FlowDelta:
    """Delta per un flusso (byte/packet rate calcolato da FlowStats)."""
    key: FlowKey
    ts: float
    bps: float
    pps: float


# ============================================================
#   SEZIONE 3 — Tipi di Azione
#  Enumerazione che definisce tutte le possibili azioni applicabili
#  dal PolicyEngine tramite Enforcer.
# ============================================================

class ActionType(Enum):
    BLOCK = auto()       # Blocco del traffico (DROP)
    UNBLOCK = auto()     # Rimozione del blocco
    LIMIT = auto()       # Rate limiting con meter
    BLACKHOLE = auto()   # Drop temporaneo verso una destinazione MAC/IP


# ============================================================
#   SEZIONE 4 — Azione (Action)
#  Struttura che incapsula una richiesta di enforcement:
#   - tipo (ActionType)
#   - entità (porta o flusso)
#   - parametri opzionali (rate, durata, destinazione)
# ============================================================

@dataclass
class Action:
    """
    Azione richiesta dalla policy.
    - key: può essere PortKey o FlowKey (per BLACKHOLE non è obbligatorio: si usano i params).
    - params:
        * LIMIT: {"rate_kbps": int}
        * BLACKHOLE: {"victim_mac": str | None, "victim_ip": str | None, "duration_s": int | None}
    """
    kind: ActionType
    key: Union[PortKey, FlowKey]
    params: dict | None = None


# ============================================================
#   FINE DEL MODULO MODELS
#  Questo file fornisce la base dati comune per tutto il sistema.
#  Ogni modulo (Monitor, Policy, Enforcer) interagisce con queste
#  strutture in modo coerente e tipizzato.
# ============================================================
