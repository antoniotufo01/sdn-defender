#!/bin/bash
BASHRC="$HOME/.bashrc"

echo "Rimozione alias SDN Defender..."

if grep -q "SDN Defender REST short commands" "$BASHRC"; then
  # Rimuove tutto il blocco fino al termine del file
  sed -i '/# === SDN Defender REST short commands ===/,$d' "$BASHRC"
  echo "Blocchi rimossi da ~/.bashrc"
else
  echo "Nessun blocco SDN Defender trovato nel file."
fi

# Ricarica la shell
source "$BASHRC"
echo "File ricaricato. I comandi SDN Defender non sono più attivi."
