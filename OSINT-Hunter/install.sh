#!/bin/bash
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${GREEN}
 ██████╗ ███████╗██╗███╗   ██╗████████╗
██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝
██║   ██║███████╗██║██╔██╗ ██║   ██║   
██║   ██║╚════██║██║██║╚██╗██║   ██║   
╚██████╔╝███████║██║██║ ╚████║   ██║   
 ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   
██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
${NC}"

echo -e "${BLUE}[*] Installing CryptDefender OSINT-Hunter V3 (14 Modules)${NC}"
echo -e "${CYAN}[*] https://github.com/cryptdefender323/OSINT-HUNTER${NC}"
echo ""

if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!] Python3 not found. Install it first!${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 --version 2>&1)
echo -e "${GREEN}[✓] Found: $PYTHON_VERSION${NC}"

echo -e "${BLUE}[*] Upgrading pip...${NC}"
python3 -m pip install --upgrade pip &> /dev/null
echo -e "${GREEN}[✓] pip upgraded${NC}"

echo -e "${BLUE}[*] Installing dependencies (this may take a moment)...${NC}"
python3 -m pip install --no-cache-dir --break-system-packages -r requirements.txt 2>/dev/null || \
python3 -m pip install --no-cache-dir -r requirements.txt &> /dev/null
echo -e "${GREEN}[✓] Dependencies installed${NC}"

mkdir -p logs results

if [ ! -f .env ]; then
    echo -e "${YELLOW}[!] No .env file found. Creating template...${NC}"
    cat > .env << 'EOF'
# Telegram
TELEGRAM_API_ID=
TELEGRAM_API_HASH=
TELEGRAM_PHONE=
SESSION_NAME=telegram_osint

# API Keys (optional but recommended)
VT_API_KEY=
SHODAN_API_KEY=
HIBP_API_KEY=
HUNTER_API_KEY=
SECURITYTRAILS_API_KEY=
ABUSEIPDB_API_KEY=
URLSCAN_API_KEY=
NUMVERIFY_API_KEY=
EMAILREP_API_KEY=
GSB_API_KEY=
PROXY_URL=
EOF
    echo -e "${GREEN}[✓] .env template created. Edit it to add your API keys.${NC}"
fi

echo ""
echo -e "${GREEN}[✓] Installation complete!${NC}"
echo -e "${CYAN}[*] Run the tools:${NC}"
echo -e "    ${YELLOW}python3 main.py${NC}"
echo ""
echo -e "${MAGENTA}[*] Modules available: 14${NC}"
echo -e "    ${CYAN}Reconnaissance:${NC} Username, Email, Domain, IP, Phone, Social"
echo -e "    ${CYAN}Threat Intel:${NC}   Dark Web, Network Vuln, Hash, URL Scanner"
echo -e "    ${CYAN}Offensive:${NC}      XSS Fuzzer, Metadata, Pastebin, Telegram"