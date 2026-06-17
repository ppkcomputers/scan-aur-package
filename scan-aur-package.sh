#!/usr/bin/env bash

# Check if a package argument was provided
if [ -z "$1" ]; then
    echo -e "\033[0;31m[-] Error: Please specify an AUR package name.\033[0m"
    echo "Usage: ai-install.sh <package-name>"
    exit 1
fi

TARGET_PKG="$1"

# Terminal formatting colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ======================================================================
# NEW: Perform System Update Before Proceeding
# ======================================================================
echo -e "${BLUE}[*] Initializing full system update (Repositories + AUR)...${NC}"
if ! yay -Syu; then
    echo -e "${RED}[-] System upgrade failed. Aborting script to avoid partial upgrade state.${NC}"
    exit 1
fi
echo -e "${GREEN}[+] System is fully up-to-date.${NC}\n"
# ======================================================================

# 1. Fetch live compromised package feeds (Atomic Arch Tracking Lists)
echo -e "${BLUE}[*] Fetching latest community lists of compromised AUR packages...${NC}"

# We pull from reliable community text repositories tracking the 1,500+ hijacked items
MALICIOUS_LIST_URL="https://raw.githubusercontent.com/aur-general/malware-tracking/main/compromised-packages.txt"
TMP_BLACKLIST=$(mktemp)

# Download the blacklist silently (with a 5-second timeout so your install isn't hung up)
curl -s --max-time 5 "$MALICIOUS_LIST_URL" -o "$TMP_BLACKLIST"

# Fallback mechanism if the live URL fails or is blocked
if [ ! -s "$TMP_BLACKLIST" ]; then
    echo -e "${YELLOW}[!] Warning: Could not fetch the live online threat list. Proceeding directly to AI evaluation layer...${NC}"
else
    # 2. Match the user's package against the blacklist
    echo -e "${BLUE}[*] Cross-referencing '${TARGET_PKG}' against known-bad repositories...${NC}"

    if grep -Fxq "$TARGET_PKG" "$TMP_BLACKLIST"; then
        echo -e "\n${RED}############################################################"
        echo -e "[-] CRITICAL SECURITY ALERT: ${TARGET_PKG} IS ON THE MALICIOUS LIST!"
        echo -e "This package was verified as hijacked or compromised during the recent attacks."
        echo -e "DO NOT PROCEED. Aborting installation immediately to protect your host."
        echo -e "############################################################${NC}\n"
        rm -f "$TMP_BLACKLIST"
        exit 1
    fi
    echo -e "${GREEN}[+] Package is clean from known automated blacklist signatures.${NC}"
fi
rm -f "$TMP_BLACKLIST"

# 3. Download the PKGBUILD/.install blueprints into memory
echo -e "${BLUE}[*] Inspecting AUR package data blueprints for ${GREEN}${TARGET_PKG}${NC}..."
pkg_data=$(yay -Gp "$TARGET_PKG" 2>/dev/null)

if [ -z "$pkg_data" ]; then
    echo -e "${RED}[-]/ Failed to retrieve AUR project data. Are you sure '${TARGET_PKG}' is a valid AUR package?${NC}"
    exit 1
fi

# 4. Pass the files directly to the local llama3.2 instance via Ollama
echo -e "${YELLOW}[*] Feeding build structure to local llama3.2 model for safety auditing...${NC}"
echo "----------------------------------------------------------------------"

AI_PROMPT="You are an expert Linux security auditor. Inspect the following Arch Linux AUR build files for malicious code injections, supply chain attacks, hidden backdoors, or privilege escalations. Check for unexpected network calls (curl/wget), malicious package managers (npm, bun, pip) pulling unauthorized tracking code like 'atomic-lockfile' or 'js-digest', obfuscated bash strings (base64, hex, eval), or unauthorized modifications to system profiles within install hooks. Keep your analysis concise. Flag any lines that look dangerous. If everything looks standard, start your response with 'STATUS: CLEAN'."

(echo "$AI_PROMPT"; echo -e "\n--- BEGIN BUILD FILES FOR $TARGET_PKG ---"; echo "$pkg_data") | ollama run llama3.2:latest

echo "----------------------------------------------------------------------"
echo -e "${YELLOW}[?] Review the local model's risk assessment above.${NC}"

# 5. Halt pipeline and request user evaluation before execution
while true; do
    read -p "Are you completely satisfied with the AI output? Proceed with installation? (y/n): " confirm
    case "$confirm" in
        [yY] )
            echo -e "${GREEN}[+] Triggering build pipeline for ${TARGET_PKG}...${NC}"
            # FIXED: Bypasses diff and edit prompts cleanly on modern versions of yay
            yay -S --aur --diffmenu=false --editmenu=false "$TARGET_PKG"
            break
            ;;
        [nN] )
            echo -e "${RED}[!] Installation safely aborted by user.${NC}"
            exit 0
            ;;
        * )
            echo "Please type 'y' (yes) or 'n' (no)."
            ;;
    esac
done
