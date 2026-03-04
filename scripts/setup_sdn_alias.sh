#!/bin/bash
# ===========================================
# SDN DEFENDER – INSTALLATORE COMANDI RAPIDI
# ===========================================

BASHRC="$HOME/.bashrc"
BASE_URL="http://127.0.0.1:8080/policy"

echo "Configurazione alias SDN Defender in corso..."

# 1. Installa jq se non presente
if ! command -v jq &> /dev/null; then
  echo "Installazione jq..."
  sudo apt install jq -y
fi

# 2. Crea il file ~/.bashrc se non esiste
if [ ! -f "$BASHRC" ]; then
  echo "Creazione nuovo file ~/.bashrc..."
  touch "$BASHRC"
fi

# 3. Aggiunge i comandi al fondo del .bashrc (solo se non già presenti)
if grep -q "SDN Defender REST short commands" "$BASHRC"; then
  echo "Alias già presenti nel file .bashrc, nessuna modifica."
else
  cat <<'EOF' >> "$BASHRC"

# === SDN Defender REST short commands ===

BASE_URL="http://127.0.0.1:8080/policy"

# ---- WHITELIST ----
wl() {
  if [ -z "$1" ]; then
    echo "Usage: wl <mac>"
    return 1
  fi
  echo -e "\033[92m[WHITELIST]\033[0m Adding MAC $1"
  curl -s -X POST "$BASE_URL/whitelist" \
    -H "Content-Type: application/json" \
    -d "{\"mac\":\"$1\"}"
  echo
}

unwl() {
  if [ -z "$1" ]; then
    echo "Usage: unwl <mac>"
    return 1
  fi
  echo -e "\033[93m[UNWHITELIST]\033[0m Removing MAC $1"
  curl -s -X DELETE "$BASE_URL/whitelist" \
    -H "Content-Type: application/json" \
    -d "{\"mac\":\"$1\"}"
  echo
}

# ---- BLOCK / UNBLOCK ----
bl() {
  if [ "$#" -ne 4 ]; then
    echo "Usage: bl <dpid> <in_port> <src_mac> <dst_mac>"
    return 1
  fi
  echo -e "\033[91m[BLOCK]\033[0m Flow $3 → $4 on dpid=$1"
  curl -s -X POST "$BASE_URL/blockflows" \
    -H "Content-Type: application/json" \
    -d "{\"dpid\":$1,\"in_port\":$2,\"eth_src\":\"$3\",\"eth_dst\":\"$4\"}"
  echo
}

unbl() {
  if [ "$#" -ne 4 ]; then
    echo "Usage: unbl <dpid> <in_port> <src_mac> <dst_mac>"
    return 1
  fi
  echo -e "\033[92m[UNBLOCK]\033[0m Flow $3 → $4 on dpid=$1"
  curl -s -X DELETE "$BASE_URL/blockflows" \
    -H "Content-Type: application/json" \
    -d "{\"dpid\":$1,\"in_port\":$2,\"eth_src\":\"$3\",\"eth_dst\":\"$4\"}"
  echo
}

# ---- VISUALIZZA LISTE ----
list_wl() {
  echo -e "\033[96m[WHITELIST]\033[0m"
  curl -s http://127.0.0.1:8080/policy/whitelist | jq
}

list_bl() {
  echo -e "\033[93m[BLOCKED FLOWS]\033[0m"
  curl -s http://127.0.0.1:8080/policy/blockflows | jq
}

# ---- MINI HELP ----
sdnhelp() {
  echo -e "\033[1m=== SDN Defender Quick Commands ===\033[0m"
  echo "wl <mac>          → aggiunge MAC alla whitelist"
  echo "unwl <mac>        → rimuove MAC dalla whitelist"
  echo "bl <dpid> <in_port> <src_mac> <dst_mac> → blocca un flusso"
  echo "unbl <dpid> <in_port> <src_mac> <dst_mac> → sblocca un flusso"
  echo "list_wl           → mostra la whitelist corrente"
  echo "list_bl           → mostra la lista dei flussi bloccati"
}
EOF

  echo "Alias SDN Defender aggiunti con successo a ~/.bashrc"
fi

# 4. Ricarica la shell
echo "Ricarico le nuove funzioni..."
source "$BASHRC"

# 5. Verifica
if type wl &>/dev/null; then
  echo "Setup completato! Prova con 'sdnhelp'"
else
  echo "Qualcosa non va: chiudi e riapri il terminale."
fi
