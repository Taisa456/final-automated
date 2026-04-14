#!/bin/bash
# ============================================================
#  AUDIT — KALI LINUX (Attacker / Auditor Machine)
#  Run: chmod +x audit_kali.sh && sudo ./audit_kali.sh
#  Output saved to ~/audit_kali.txt
# ============================================================

LOG="$HOME/audit_kali.txt"
DATE=$(date '+%Y-%m-%d %H:%M')

# --- FILL IN IP ADDRESSES BEFORE RUNNING ---
SERVER_IP="192.168.X.X"      # Main Server (Windows Server + AD)
OPERATOR_IP="192.168.X.X"    # Operator Machine (Windows 10/11)
META_IP="192.168.X.X"        # Metasploitable 2
# -------------------------------------------

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

section() {
    echo -e "\n${CYAN}$(printf '=%.0s' {1..60})${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}$(printf '=%.0s' {1..60})${NC}"
    echo -e "\n$(printf '=%.0s' {1..60})\n  $1\n$(printf '=%.0s' {1..60})" >> "$LOG"
}

result() {
    local label="$1" value="$2" status="$3"
    local color=$NC
    case $status in
        OK)   color=$GREEN ;;
        FAIL) color=$RED ;;
        RISK) color=$YELLOW ;;
    esac
    echo -e "  ${color}[$status] $label : $value${NC}"
    echo "  [$status] $label : $value" >> "$LOG"
}

cat > "$LOG" << EOF
============================================================
  SECURITY AUDIT — KALI LINUX
  Date: $DATE
============================================================
EOF
echo -e "${CYAN}============================================================"
echo "  SECURITY AUDIT — KALI LINUX"
echo "  Date: $DATE"
echo -e "============================================================${NC}"

# ============================================================
# SECTION 1: INTERNET ACCESS FROM KALI (should be available)
# ============================================================
section "1. INTERNET ACCESS FROM KALI (should be available)"

if ping -c 2 -W 3 8.8.8.8 &>/dev/null; then
    result "Internet (8.8.8.8)" "Reachable" "OK"
else
    result "Internet (8.8.8.8)" "No access" "FAIL"
fi

if curl -s --max-time 5 https://google.com -o /dev/null; then
    result "HTTPS google.com" "Reachable" "OK"
else
    result "HTTPS google.com" "No access" "FAIL"
fi

# ============================================================
# SECTION 2: ANYDESK INSTALLED AND RUNNING
# ============================================================
section "2. ANYDESK INSTALLED AND RUNNING"

if command -v anydesk &>/dev/null; then
    result "AnyDesk installed" "Yes" "OK"
    if pgrep -x anydesk &>/dev/null; then
        result "AnyDesk running" "Yes" "OK"
    else
        result "AnyDesk running" "No — start it manually" "FAIL"
    fi
else
    result "AnyDesk" "Not installed" "FAIL"
fi

# ============================================================
# SECTION 3: KALI → OPERATOR RDP CONNECTIVITY
# ============================================================
section "3. KALI → OPERATOR RDP CONNECTIVITY (port 3389)"

echo "  Checking RDP port on Operator ($OPERATOR_IP:3389)..." | tee -a "$LOG"
if timeout 5 bash -c "echo > /dev/tcp/$OPERATOR_IP/3389" 2>/dev/null; then
    result "RDP port 3389 on Operator" "Open" "OK"
else
    result "RDP port 3389 on Operator" "Closed or unreachable" "FAIL"
fi

echo "  Testing xfreerdp connection (authentication check only)..." | tee -a "$LOG"
timeout 8 xfreerdp /v:$OPERATOR_IP /port:3389 /cert-ignore /auth-only /u:test /p:wrongpass 2>&1 | \
    grep -E "ERRCONNECT|NLA|connect|Authentication" | tee -a "$LOG" | head -5

# ============================================================
# SECTION 4: PORT SCAN — OPERATOR MACHINE
# ============================================================
section "4. PORT SCAN — OPERATOR MACHINE ($OPERATOR_IP)"

echo "  Nmap scan of Operator..." | tee -a "$LOG"
nmap -sV -p 135,139,445,3389,5985 --open $OPERATOR_IP 2>&1 | tee -a "$LOG"

echo -e "\n  SMB shares on Operator (anonymous):" | tee -a "$LOG"
smbclient -L //$OPERATOR_IP -N 2>&1 | tee -a "$LOG"

# ============================================================
# SECTION 5: PORT SCAN — MAIN SERVER
# ============================================================
section "5. PORT SCAN — MAIN SERVER ($SERVER_IP)"

echo "  Nmap scan of Main Server..." | tee -a "$LOG"
nmap -sV -p 53,80,135,139,389,443,445,3268,3389 --open $SERVER_IP 2>&1 | tee -a "$LOG"

echo -e "\n  Enum4linux — AD users without authentication:" | tee -a "$LOG"
if command -v enum4linux &>/dev/null; then
    enum4linux -U $SERVER_IP 2>&1 | grep -E "user:|Group:|password|Account" | head -20 | tee -a "$LOG"
else
    result "enum4linux" "Not installed. Install: apt install enum4linux" "FAIL"
fi

echo -e "\n  SMB vulnerability check (EternalBlue etc.):" | tee -a "$LOG"
nmap --script smb-vuln* -p 445 $SERVER_IP 2>&1 | tee -a "$LOG"

# ============================================================
# SECTION 6: SEGMENTATION — KALI MUST NOT REACH METASPLOITABLE
# ============================================================
section "6. SEGMENTATION — KALI MUST NOT REACH METASPLOITABLE ($META_IP)"

echo "  Attempting to reach Metasploitable from Kali..." | tee -a "$LOG"

if ping -c 2 -W 3 $META_IP &>/dev/null; then
    result "Ping Kali → Meta" "SUCCESS — segmentation is BROKEN!" "FAIL"
else
    result "Ping Kali → Meta" "Timeout — segmentation is working" "OK"
fi

echo "  Nmap port scan of Meta from Kali (all ports should be closed):" | tee -a "$LOG"
nmap -Pn -p 21,22,23,80,3306 --open $META_IP 2>&1 | tee -a "$LOG"
OPEN_PORTS=$(nmap -Pn -p 21,22,23,80,3306 $META_IP 2>&1 | grep "open" | wc -l)
if [ "$OPEN_PORTS" -gt 0 ]; then
    result "Meta ports visible from Kali" "$OPEN_PORTS port(s) open — SEGMENTATION VIOLATION!" "FAIL"
else
    result "Meta ports from Kali" "All closed — OK" "OK"
fi

# ============================================================
# SECTION 7: KALI → MAIN SERVER REACHABILITY
# ============================================================
section "7. KALI → MAIN SERVER REACHABILITY"

if ping -c 2 -W 3 $SERVER_IP &>/dev/null; then
    result "Ping Kali → Main Server" "Reachable" "OK"
else
    result "Ping Kali → Main Server" "Unreachable — check routing" "FAIL"
fi

# ============================================================
# SECTION 8: LLMNR / NBT-NS INTERCEPTION (Responder)
# ============================================================
section "8. LLMNR/NBT-NS INTERCEPTION TEST (Responder)"

if command -v responder &>/dev/null; then
    result "Responder" "Installed — run separately: sudo responder -I eth0 -rdw" "OK"
    echo "  IMPORTANT: Run Responder in a separate terminal and capture a screenshot for the report." | tee -a "$LOG"
else
    result "Responder" "Not found. Install: apt install responder" "FAIL"
fi

# ============================================================
# SECTION 9: PASSWORD VALIDATION — P455w0rd (CrackMapExec)
# ============================================================
section "9. PASSWORD CHECK — P455w0rd via CrackMapExec"

if command -v crackmapexec &>/dev/null || command -v cme &>/dev/null; then
    CME=$(command -v crackmapexec || command -v cme)
    echo "  Testing password P455w0rd against Main Server..." | tee -a "$LOG"
    for user in "production1" "prod1" "user1" "operator"; do
        $CME smb $SERVER_IP -u "$user" -p "P455w0rd" 2>&1 | grep -E "\+|-|Pwn3d" | tee -a "$LOG"
    done
    echo "  Get exact username from enum4linux output above and re-test." | tee -a "$LOG"
else
    result "crackmapexec" "Not installed. Install: apt install crackmapexec" "RISK"
fi

# ============================================================
# SECTION 10: IPv6 FIREWALL BYPASS CHECK
# ============================================================
section "10. IPv6 — POTENTIAL IPv4 FIREWALL BYPASS"

echo "  Kali IPv6 address:" | tee -a "$LOG"
ip -6 addr show | grep "inet6" | grep -v "::1" | tee -a "$LOG"

echo "  Attempting IPv6 communication with Main Server:" | tee -a "$LOG"
SERVER_IPV6=$(ping6 -c 1 $SERVER_IP 2>/dev/null | grep "from" | awk '{print $4}' | tr -d ':')
if [ -n "$SERVER_IPV6" ]; then
    result "IPv6 link to Main Server" "Works — check if IPv6 firewall rules exist!" "RISK"
else
    result "IPv6 link to Main Server" "No response" "OK"
fi

# ============================================================
# SECTION 11: SSL/TLS WEAK CIPHERS ON MAIN SERVER
# ============================================================
section "11. SSL/TLS WEAK CIPHERS ON MAIN SERVER"

echo "  Checking SSL/TLS cipher strength on Server (ports 443, 8443)..." | tee -a "$LOG"
nmap --script ssl-enum-ciphers -p 443,8443 $SERVER_IP 2>&1 | grep -E "TLS|SSL|cipher|WEAK" | tee -a "$LOG"

# ============================================================
# SECTION 12: REACHABILITY SUMMARY TABLE
# ============================================================
section "12. FULL REACHABILITY MATRIX (Kali as source)"

echo "  Testing all targets from Kali..." | tee -a "$LOG"

for TARGET_NAME in "Main_Server:$SERVER_IP" "Operator:$OPERATOR_IP" "Metasploitable:$META_IP"; do
    NAME="${TARGET_NAME%%:*}"
    IP="${TARGET_NAME##*:}"
    if ping -c 2 -W 3 "$IP" &>/dev/null; then
        if [[ "$NAME" == "Metasploitable" ]]; then
            result "Kali → $NAME ($IP)" "REACHABLE — should be BLOCKED!" "FAIL"
        else
            result "Kali → $NAME ($IP)" "Reachable" "OK"
        fi
    else
        if [[ "$NAME" == "Metasploitable" ]]; then
            result "Kali → $NAME ($IP)" "Timeout — segmentation correct" "OK"
        else
            result "Kali → $NAME ($IP)" "Unreachable — check routing" "FAIL"
        fi
    fi
done

# ============================================================
# FOOTER
# ============================================================
FOOTER="
============================================================
  AUDIT COMPLETE: $DATE
  Log saved to: $LOG
============================================================
  QUICK FILTER:
  grep '\[FAIL\]' $LOG
  grep '\[RISK\]' $LOG
============================================================
  NEXT STEP: Run audit_metasploitable.sh from this machine
             OR from Metasploitable itself (local checks)
============================================================"
echo "$FOOTER" | tee -a "$LOG"
echo -e "${CYAN}$FOOTER${NC}"
