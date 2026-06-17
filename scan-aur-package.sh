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
# 1. Perform System Update Before Proceeding
# ======================================================================
echo -e "${BLUE}[*] Initializing full system update (Repositories + AUR)...${NC}"
if ! yay -Syu; then
    echo -e "${RED}[-] System upgrade failed. Aborting script to avoid partial upgrade state.${NC}"
    exit 1
fi
echo -e "${GREEN}[+] System is fully up-to-date.${NC}\n"

# ======================================================================
# 2. Fetch live compromised package feeds (Atomic Arch Tracking Lists)
# ======================================================================
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
    # Match the user's package against the blacklist
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

# ======================================================================
# 3. Dynamic LLM Environment Assessment
# ======================================================================
RUN_AI_AUDIT=true
CHOSEN_MODEL=""

# Check if ollama command exists and the daemon is running
if ! command -v ollama &> /dev/null || ! curl -s http://localhost:11434/api/tags &> /dev/null; then
    echo -e "${YELLOW}[!] Warning: Ollama is either not installed or the daemon is not running.${NC}"
    echo -e "${YELLOW}[!] Skipping AI security audit phase.${NC}"
    RUN_AI_AUDIT=false
fi

if [ "$RUN_AI_AUDIT" = true ]; then
    echo -e "${BLUE}[*] Checking local Ollama instance for usable models...${NC}"
    
    # Check specifically for llama3.2:latest first
    if ollama list | grep -q -E "llama3\.2:latest"; then
        CHOSEN_MODEL="llama3.2:latest"
        echo -e "${GREEN}[+] Found preferred model: ${CHOSEN_MODEL}${NC}"
    else
        # If llama3.2:latest isn't there, look for ANY other model containing the word "llama"
        ANY_LLAMA=$(ollama list | grep -i "llama" | awk '{print $1}' | head -n 1)
        
        if [ -n "$ANY_LLAMA" ]; then
            CHOSEN_MODEL="$ANY_LLAMA"
            echo -e "${YELLOW}[!] llama3.2:latest not found, but detected alternative fallback: ${CHOSEN_MODEL}${NC}"
        else
            # No llama models exist at all. Prompt user to install llama3.2:latest
            echo -e "${YELLOW}[!] No 'llama' models detected on your local system.${NC}"
            while true; do
                read -p "Would you like to pull/install 'llama3.2:latest' now? (y/n): " download_confirm
                case "$download_confirm" in
                    [yY] )
                        echo -e "${BLUE}[*] Pulling llama3.2:latest via Ollama... (This might take a moment)${NC}"
                        if ollama pull llama3.2:latest; then
                            CHOSEN_MODEL="llama3.2:latest"
                            echo -e "${GREEN}[+] Successfully downloaded llama3.2:latest.${NC}"
                        else
                            echo -e "${RED}[-] Failed to download model. Skipping AI audit layer.${NC}"
                            RUN_AI_AUDIT=false
                        fi
                        break
                        ;;
                    [nN] )
                        echo -e "${YELLOW}[!] Skipping AI audit layer by user request.${NC}"
                        RUN_AI_AUDIT=false
                        break
                        ;;
                    * )
                        echo "Please type 'y' (yes) or 'n' (no)."
                        ;;
                esac
            done
        fi
    fi
fi

# ======================================================================
# NEW: Prompt to Skip Scan (Only if AI environment is actually available)
# ======================================================================
if [ "$RUN_AI_AUDIT" = true ] && [ -n "$CHOSEN_MODEL" ]; then
    while true; do
        read -p "Do you want to run the AI security scan on this package? (y/n): " scan_confirm
        case "$scan_confirm" in
            [yY] )
                # Keep RUN_AI_AUDIT as true and proceed
                break
                ;;
            [nN] )
                echo -e "${YELLOW}[!] Bypassing AI scan by user choice.${NC}"
                RUN_AI_AUDIT=false
                break
                ;;
            * )
                echo "Please type 'y' (yes) or 'n' (no)."
                ;;
        esac
    done
fi

# ======================================================================
# 4. Download and Scan Package Blueprints (If AI Enabled)
# ======================================================================
if [ "$RUN_AI_AUDIT" = true ] && [ -n "$CHOSEN_MODEL" ]; then
    echo -e "${BLUE}[*] Inspecting AUR package data blueprints for ${GREEN}${TARGET_PKG}${NC}..."
    pkg_data=$(yay -Gp "$TARGET_PKG" 2>/dev/null)

    if [ -z "$pkg_data" ]; then
        echo -e "${RED}[-]/ Failed to retrieve AUR project data. Are you sure '${TARGET_PKG}' is a valid AUR package?${NC}"
        exit 1
    fi

    echo -e "${YELLOW}[*] Feeding build structure to local ${CHOSEN_MODEL} model for safety auditing...${NC}"
    echo "----------------------------------------------------------------------"

    AI_PROMPT="You are an expert Linux security auditor. Inspect the following Arch Linux AUR build files for malicious code injections, supply chain attacks, hidden backdoors, or privilege escalations. Check for unexpected network calls (curl/wget), malicious package managers (npm, bun, pip) pulling unauthorized tracking code like 'atomic-lockfile' or 'js-digest', obfuscated bash strings (base64, hex, eval), or unauthorized modifications to system profiles within install hooks. Keep your analysis concise. Flag any lines that look dangerous. If everything looks standard, start your response with 'STATUS: CLEAN'."

    (echo "$AI_PROMPT"; echo -e "\n--- BEGIN BUILD FILES FOR $TARGET_PKG ---"; echo "$pkg_data") | ollama run "$CHOSEN_MODEL"

    echo "----------------------------------------------------------------------"
    echo -e "${YELLOW}[?] Review the local model's risk assessment above.${NC}"

    # Request manual evaluation confirmation after AI output
    while true; do
        read -p "Are you completely satisfied with the AI output? Proceed with installation? (y/n): " confirm
        case "$confirm" in
            [yY] )
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
else
    # Fallback gatekeeper if AI scanning was skipped or disabled
    echo -e "${YELLOW}[!] Proceeding without an AI security audit.${NC}"
    while true; do
        read -p "Do you want to proceed with installing ${TARGET_PKG} anyway? (y/n): " raw_confirm
        case "$raw_confirm" in
            [yY] )
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
fi

# ======================================================================
# 5. Execute Package Build Pipeline
# ======================================================================
echo -e "${GREEN}[+] Triggering build pipeline for ${TARGET_PKG}...${NC}"
# Bypasses diff and edit prompts cleanly on modern versions of yay
yay -S --aur --diffmenu=false --editmenu=false "$TARGET_PKG"
