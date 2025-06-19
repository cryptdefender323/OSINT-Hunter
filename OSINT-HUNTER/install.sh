#!/bin/bash

echo -e "\033[1;34m[*] Installing CryptDefender OSINT Tools\033[0m"

if ! command -v python3 &> /dev/null; then
    echo -e "\033[1;31m[!] Python3 tidak ditemukan. Silakan install terlebih dahulu.\033[0m"
    exit 1
fi

echo -e "\033[1;34m[*] Memperbarui pip...\033[0m"
python3 -m pip install --upgrade pip

echo -e "\033[1;34m[*] Menginstal dependensi utama...\033[0m"
pip install --break-system-packages -r requirements.txt

mkdir -p logs

echo -e "\033[1;32m[✓] Instalasi selesai!\033[0m"
echo -e "\033[1;36m[*] Jalankan tools:\033[0m"
echo -e "    \033[1;33mpython3 main.py\033[0m"
