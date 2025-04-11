#!/bin/bash

green="\033[1;32m"
yellow="\033[1;33m"
red="\033[1;31m"
blue="\033[1;34m"
blink="\033[5m"
reset="\033[0m"

clear
echo -e "${blink}${green}Please be patient... installing CryptDefender OSINT Vault Tools 🔧${reset}"
sleep 2

if ! command -v python3 &>/dev/null; then
    echo -e "${red}[!] Python3 not found. Please install Python3 first.${reset}"
    exit 1
fi

if ! command -v pip3 &>/dev/null; then
    echo -e "${yellow}[~] Pip3 not found. Installing pip3...${reset}"
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        sudo apt update && sudo apt install python3-pip -y
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        brew install python3
    else
        echo -e "${red}✘ Unsupported OS. Please install pip3 manually.${reset}"
        exit 1
    fi
fi

echo -ne "${yellow}[*] Installing optional stealth (Tor)...${reset}"
{ sudo apt install -y tor torsocks > /dev/null 2>&1; } || true
echo -e "${green} Done!${reset}"

echo -ne "${yellow}[*] Installing Python modules...${reset}"
{ pip3 install -r requirements.txt --quiet --break-system-packages; } || true
echo -e "${green} Done!${reset}"

echo -e "\n${green}[✓] Installation complete! Jalankan tools dengan:${reset}"
echo -e "${blue}python3 main.py${reset}"
