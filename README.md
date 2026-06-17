# scan-aur-package
# AUR Package Security Scanner
A bash script designed to audit AUR packages before installation. It scans packages against a blacklist of known compromised entries and optionally leverages a local AI model via Ollama to analyze PKGBUILD and *.install files for potential malware, obfuscated code, or unauthorized remote network calls.

Features
Blacklist Verification: Checks target AUR packages against a list of known compromised or flagged packages.

Local AI Auditing (Optional): Utilizes a locally hosted LLM to inspect installation scripts for malicious behavior, ensuring your code analysis remains completely private.

Zero-Touch Privacy: No code or telemetry is sent to external cloud APIs when using the AI features.

Prerequisites
Core Dependencies
Ensure you have the standard Arch build essentials installed:

bash

git

pacman (and an AUR helper if integrating into workflows)

Optional AI Analysis
To enable local AI inspection of package files, you must have Ollama installed and running with the specific model pulled:

Install and start Ollama on your system.

Download the required model:

Bash
ollama run llama3.2:3b
💡 Note: If Ollama or the llama3.2:3b model is missing, you can simply opt out of the AI analysis when prompted by the script, and it will still perform the standard blacklist check.

Usage
Navigate to the directory containing the script, ensure it is executable, and pass the desired AUR package name as an argument.

Bash
# Make the script executable (only needed once)
chmod +x scan-aur-package.sh

# Run the scanner against a package (e.g., fastfetch)
./scan-aur-package.sh fastfetch

Watch the video here:
https://youtu.be/_FBGMWpJiws
