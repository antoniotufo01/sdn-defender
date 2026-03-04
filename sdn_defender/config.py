# sdn_defender/config.py
# ============================================================
#   MODULO CONFIG
#  Contiene tutti i parametri di configurazione del sistema SDN Defender.
#  L’obiettivo è permettere la modifica dei comportamenti (polling,
#  soglie, enforcement, DDoS, ecc.) senza toccare il codice dei moduli.
# ============================================================

CFG = {
    # ========================================================
    #   SEZIONE 1 — MONITOR
    #  Parametri relativi al polling delle statistiche OpenFlow.
    #  Definiscono la frequenza di raccolta dati e la finestra
    #  temporale di memoria nel DataStore.
    # ========================================================

    "poll_interval_s": 1.0,       # intervallo di polling delle statistiche (in secondi)
    "stats_window_s": 12,         # finestra temporale conservata nel datastore (in secondi)

    # ========================================================
    #   SEZIONE 2 — POLICY ENGINE
    #  Parametri di base per la logica di detection e threshold.
    #  La soglia è inizialmente fissa ma può essere adattiva (EWMA).
    # ========================================================

    "threshold_bps": 2_000_000,   # soglia base di throughput per bloccare (≈ 2 Mbps)
    "consec_block": 1,            # numero di tick consecutivi sopra soglia per bloccare
    "consec_unblock": 1,          # tick consecutivi sotto soglia per sbloccare
    "limit_rate_kbps": 1000,      # velocità limite per rate limiting (1 Mbps)

    # ========================================================
    #   SEZIONE 3 — ENFORCEMENT
    #  Definisce le priorità e i parametri OpenFlow utilizzati
    #  per installare regole di DROP, LIMIT o TABLE-MISS.
    # ========================================================

    "drop_priority": 200,         # priorità delle regole di drop
    "table_miss_priority": 0,     # priorità della regola table-miss
}

# ============================================================
#   SEZIONE 4 — Rilevamento e Mitigazione a Livello di FLUSSO
#  Parametri per l’analisi basata su flussi (L2/L3) e il controllo
#  granulare del traffico anomalo.
# ============================================================

CFG.update({
    "detect_scope": "flow",            # "flow" = analisi per flusso, "port" = analisi per porta
    "flow_match_level": "l2",          # livello di matching: "l2" (MAC) o "l3" (IP)
    "whitelist_macs": [],              # MAC da non bloccare mai (es. ["00:00:00:00:00:01"])
    "block_hard_timeout_s": 8,         # durata minima del blocco (secondi)
    "block_idle_timeout_s": 0,         # 0 = non scade per inattività

    # ========================================================
    #   SEZIONE 5 — REST API (WSGI)
    #  Abilita e configura l’interfaccia REST integrata in Ryu
    #  per la gestione dinamica di whitelist e blocklist.
    # ========================================================

    "enable_rest_api": True,           # abilita server REST interno
    "rest_app_name": "sdndefender_api",# nome dell’app Ryu WSGI per il registro API

    # Whitelist di base (configurazione iniziale)
    "whitelist_macs": [],              # lista iniziale, poi estendibile via API

    # ========================================================
    #   SEZIONE 6 — Rilevamento Burst / Stealth DoS
    #  Parametri per l’analisi statistica di breve periodo:
    #   - identifica pattern “bursty” o traffico oscillante
    #   - evita falsi positivi da spike momentanei
    # ========================================================

    "burst_window_s": 10,              # finestra temporale per l’analisi del burst (in secondi)
    "burst_cv_min": 0.3,               # coefficiente di variazione minimo (std/mean)
    "burst_peak_ratio": 1.5,           # rapporto picco/EWMA minimo per considerare burst
    "micro_threshold_bps": 100_000,    # soglia micro per ignorare rumore intermittente (100 kbps)

    # ========================================================
    #   SEZIONE 7 — Rilevamento DDoS Aggregato
    #  Parametri per la rilevazione distribuita di DDoS:
    #   - somma traffico su stessa destinazione
    #   - attiva blackhole se condizione sostenuta
    # ========================================================

    "ddos_enable": True,               # abilita detection DDoS
    "ddos_min_flows": 3,               # minimo numero di flussi “attivi” verso stessa destinazione
    "ddos_dst_threshold_bps": 1_000_000,  # soglia di traffico aggregato (≈ 1 Mbps)
    "ddos_block_top_n": 2,             # numero di flussi principali da bloccare
    "ddos_cooldown_s": 5,              # tempo minimo tra due mitigazioni successive (in secondi)

    # ========================================================
    #   SEZIONE 8 — Unblock e Blackhole
    #  Parametri per il rilascio graduale dei blocchi e la
    #  gestione dei blackhole temporanei.
    # ========================================================

    "unblock_cooldown_s": 120,         # tempo minimo prima di poter sbloccare un flusso (in secondi)

    "blackhole_enable": True,          # abilita blackhole DDoS
    "blackhole_duration_s": 20,        # durata del blackhole (auto-rimozione dopo N secondi)
})

# ============================================================
#   FINE DEL MODULO CONFIG
#  Tutti i moduli (Monitor, Policy, Enforcer, Controller) leggono
#  direttamente da CFG. Ogni parametro può essere adattato senza
#  modificare il codice, rendendo SDN Defender altamente modulare.
# ============================================================
