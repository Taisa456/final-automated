# ============================================================
#  AUDIT — MAIN SERVER (Windows Server + Active Directory)
#  Run as Administrator on the Main Server
#  Output saved to C:\audit_main_server.txt
#
#  Usage: Right-click PowerShell -> "Run as Administrator"
#         Set-ExecutionPolicy Bypass -Scope Process -Force
#         .\audit_main_server.ps1
# ============================================================

$LOG = "C:\audit_main_server.txt"
$DATE = Get-Date -Format "yyyy-MM-dd HH:mm"

# --- FILL IN IP ADDRESSES BEFORE RUNNING ---
$OPERATOR_IP = "192.168.X.X"   # Operator Machine (Windows 10/11)
$META_IP     = "192.168.X.X"   # Metasploitable 2
$KALI_IP     = "192.168.X.X"   # Kali Linux (attacker)
# -------------------------------------------

function Write-Section($title) {
    $line = "`n" + ("=" * 60) + "`n  $title`n" + ("=" * 60)
    Write-Host $line -ForegroundColor Cyan
    Add-Content $LOG $line
}

function Write-Result($label, $value, $status = "") {
    $colors = @{ "OK" = "Green"; "FAIL" = "Red"; "RISK" = "Yellow"; "" = "White" }
    $color = if ($colors[$status]) { $colors[$status] } else { "White" }
    $line = "  [$status] $label : $value"
    Write-Host $line -ForegroundColor $color
    Add-Content $LOG $line
}

# Header
$header = @"
============================================================
  SECURITY AUDIT — MAIN SERVER
  Date: $DATE
============================================================
"@
Set-Content $LOG $header
Write-Host $header -ForegroundColor White

# ============================================================
# SECTION 1: NETWORK INTERFACES
# ============================================================
Write-Section "1. NETWORK INTERFACES (expected: 3 adapters)"

$adapters = Get-NetIPConfiguration | Where-Object { $_.IPv4Address }
$adapterCount = $adapters.Count
$status = if ($adapterCount -ge 3) { "OK" } else { "FAIL" }
Write-Result "Adapters with IP address" $adapterCount $status

Add-Content $LOG "`n  Adapter details:"
foreach ($a in $adapters) {
    $info = "    - $($a.InterfaceAlias) : $($a.IPv4Address.IPAddress)"
    Write-Host $info
    Add-Content $LOG $info
}

# ============================================================
# SECTION 2: ACTIVE DIRECTORY USERS
# ============================================================
Write-Section "2. ACTIVE DIRECTORY — USERS (expected: exactly 5)"

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $users = Get-ADUser -Filter * -Properties Description, PasswordNeverExpires, PasswordLastSet, MemberOf
    $userCount = $users.Count
    $status = if ($userCount -eq 5) { "OK" } elseif ($userCount -gt 0) { "RISK" } else { "FAIL" }
    Write-Result "Total users in AD" $userCount $status

    Add-Content $LOG "`n  User list:"
    foreach ($u in $users) {
        $desc    = if ($u.Description) { "DESCRIPTION: '$($u.Description)'" } else { "no description" }
        $neverExp = if ($u.PasswordNeverExpires) { "PASSWORD NEVER EXPIRES!" } else { "password policy OK" }
        $line = "    - $($u.SamAccountName) | $desc | $neverExp | Last changed: $($u.PasswordLastSet)"
        Write-Host $line -ForegroundColor $(if ($u.PasswordNeverExpires -or $u.Description) { "Yellow" } else { "White" })
        Add-Content $LOG $line
    }
} catch {
    Write-Result "AD module unavailable" $_.Exception.Message "FAIL"
}

# ============================================================
# SECTION 3: DOMAIN ADMINS GROUP
# ============================================================
Write-Section "3. DOMAIN ADMINS GROUP (expected: only 1 Admin account)"

try {
    $domainAdmins = Get-ADGroupMember "Domain Admins"
    $count = $domainAdmins.Count
    $status = if ($count -eq 1) { "OK" } else { "RISK" }
    Write-Result "Members in Domain Admins" $count $status
    foreach ($m in $domainAdmins) {
        $line = "    - $($m.Name) ($($m.ObjectClass))"
        Write-Host $line -ForegroundColor $(if ($count -gt 1) { "Yellow" } else { "White" })
        Add-Content $LOG $line
    }
} catch {
    Write-Result "Error checking Domain Admins" $_.Exception.Message "FAIL"
}

# ============================================================
# SECTION 4: REMOTE DESKTOP USERS GROUP
# ============================================================
Write-Section "4. REMOTE DESKTOP USERS GROUP (should not contain Everyone/Domain Users)"

try {
    $rdpUsers = Get-ADGroupMember "Remote Desktop Users" -ErrorAction SilentlyContinue
    if ($rdpUsers) {
        foreach ($m in $rdpUsers) {
            $isRisky = ($m.Name -in @("Everyone", "Authenticated Users", "Domain Users"))
            $status = if ($isRisky) { "RISK" } else { "OK" }
            Write-Result "RDP member" $m.Name $status
        }
    } else {
        Write-Result "Remote Desktop Users" "Group is empty" "OK"
    }
} catch {
    Write-Result "Error" $_.Exception.Message "FAIL"
}

# ============================================================
# SECTION 5: PASSWORD NEVER EXPIRES
# ============================================================
Write-Section "5. USERS WITH 'PASSWORD NEVER EXPIRES'"

try {
    $neverExpire = Get-ADUser -Filter {PasswordNeverExpires -eq $true} -Properties PasswordNeverExpires
    if ($neverExpire) {
        foreach ($u in $neverExpire) {
            Write-Result "Password Never Expires" $u.SamAccountName "RISK"
        }
    } else {
        Write-Result "Password Never Expires" "Not set for any user" "OK"
    }
} catch {
    Write-Result "Error" $_.Exception.Message "FAIL"
}

# ============================================================
# SECTION 6: DOMAIN PASSWORD POLICY
# ============================================================
Write-Section "6. DOMAIN PASSWORD POLICY"

try {
    $policy = Get-ADDefaultDomainPasswordPolicy
    $minLen  = $policy.MinPasswordLength
    $lockout = $policy.LockoutThreshold
    $maxAge  = $policy.MaxPasswordAge.Days

    $statusLen  = if ($minLen -ge 8)                          { "OK" } else { "FAIL" }
    $statusLock = if ($lockout -gt 0)                         { "OK" } else { "RISK" }
    $statusAge  = if ($maxAge -gt 0 -and $maxAge -le 90)      { "OK" } else { "RISK" }

    Write-Result "Minimum password length"       $minLen  $statusLen
    Write-Result "Account lockout threshold"     $lockout $statusLock
    Write-Result "Maximum password age (days)"   $maxAge  $statusAge
    Write-Result "Password history count"        $policy.PasswordHistoryCount ""
} catch {
    Write-Result "Error" $_.Exception.Message "FAIL"
}

# ============================================================
# SECTION 7: PASSWORD TEST — P455w0rd (Production user)
# ============================================================
Write-Section "7. PASSWORD CHECK — P455w0rd (Production User)"

Add-Content $LOG "  Attempting login as Production user with password P455w0rd..."
try {
    $prodUser = Get-ADUser -Filter * |
        Where-Object { $_.SamAccountName -notlike "*admin*" -and $_.SamAccountName -notlike "*support*" } |
        Select-Object -First 1
    if ($prodUser) {
        $domain = (Get-ADDomain).NetBIOSName
        try {
            $null = New-Object System.DirectoryServices.DirectoryEntry(
                "LDAP://$(hostname)",
                "$domain\$($prodUser.SamAccountName)",
                "P455w0rd"
            )
            Write-Result "Login with P455w0rd" "SUCCESS — password matches!" "RISK"
        } catch {
            Write-Result "Login with P455w0rd" "Failed — wrong password or account locked" "OK"
        }
    } else {
        Write-Result "Production user" "Not found" "FAIL"
    }
} catch {
    Add-Content $LOG "  Manual check required: try logging in as a Production user with password P455w0rd"
}

# ============================================================
# SECTION 8: FIREWALL RULES (RDP inbound + Kali isolation)
# ============================================================
Write-Section "8. FIREWALL RULES (RDP from outside + Kali block)"

$rdpRules = Get-NetFirewallRule |
    Where-Object { $_.DisplayName -like "*RDP*" -or $_.DisplayName -like "*Remote Desktop*" } |
    Select-Object DisplayName, Direction, Action, Enabled

if ($rdpRules) {
    Add-Content $LOG "  RDP firewall rules:"
    foreach ($r in $rdpRules) {
        $line = "    - $($r.DisplayName) | Direction: $($r.Direction) | Action: $($r.Action) | Enabled: $($r.Enabled)"
        $color = if ($r.Action -eq "Allow" -and $r.Direction -eq "Inbound") { "Yellow" } else { "White" }
        Write-Host $line -ForegroundColor $color
        Add-Content $LOG $line
    }
} else {
    Write-Result "RDP rules" "None found" "RISK"
}

# Check for explicit Kali block rule
$kaliBlock = Get-NetFirewallRule | Where-Object { $_.DisplayName -like "*Kali*" -or $_.DisplayName -like "*attacker*" }
if ($kaliBlock) {
    Write-Result "Kali block rule" "Rule exists: $($kaliBlock.DisplayName)" "OK"
} else {
    Write-Result "Kali block rule" "No explicit rule found — verify routing/VLAN isolation" "RISK"
}

# ============================================================
# SECTION 9: LOGON AUDIT POLICY (brute-force detection)
# ============================================================
Write-Section "9. LOGON AUDIT POLICY (brute-force visibility)"

$auditPolicy = auditpol /get /subcategory:"Logon" 2>&1
$auditLine   = $auditPolicy | Where-Object { $_ -match "Logon" }
Add-Content $LOG "  Current logon audit policy:`n  $auditLine"
Write-Host "  $auditLine"

$failureEvents = Get-EventLog -LogName Security -EntryType FailureAudit -Newest 5 -ErrorAction SilentlyContinue
if ($failureEvents) {
    Write-Result "Recent failed logon events" "$($failureEvents.Count) found (last 5)" "OK"
} else {
    Write-Result "Failed logon events in log" "None found — audit may be disabled" "RISK"
}

# ============================================================
# SECTION 10: OPEN LISTENING PORTS ON SERVER
# ============================================================
Write-Section "10. OPEN LISTENING PORTS ON THIS SERVER"

$ports      = Get-NetTCPConnection -State Listen | Select-Object LocalPort, OwningProcess | Sort-Object LocalPort -Unique
$riskyPorts = @(21, 23, 80, 445)
foreach ($p in $ports) {
    $proc   = (Get-Process -Id $p.OwningProcess -ErrorAction SilentlyContinue).Name
    $status = if ($p.LocalPort -in $riskyPorts) { "RISK" } else { "" }
    Write-Result "Listening port" "$($p.LocalPort) ($proc)" $status
}

# ============================================================
# SECTION 11: SEGMENTATION — SERVER → META AND KALI REACHABILITY
# ============================================================
Write-Section "11. NETWORK SEGMENTATION CHECKS (from Main Server)"

Add-Content $LOG "  Testing reachability to other machines..."

# Server should reach Metasploitable (same internal segment)
$pingMeta = Test-Connection -ComputerName $META_IP -Count 2 -Quiet -ErrorAction SilentlyContinue
$status = if ($pingMeta) { "OK" } else { "FAIL" }
Write-Result "Ping Server → Metasploitable ($META_IP)" $(if ($pingMeta) { "Reachable" } else { "Unreachable" }) $status

# Server should reach Operator
$pingOp = Test-Connection -ComputerName $OPERATOR_IP -Count 2 -Quiet -ErrorAction SilentlyContinue
$status = if ($pingOp) { "OK" } else { "FAIL" }
Write-Result "Ping Server → Operator ($OPERATOR_IP)" $(if ($pingOp) { "Reachable" } else { "Unreachable" }) $status

# Kali should NOT be reachable from Server
$pingKali = Test-Connection -ComputerName $KALI_IP -Count 2 -Quiet -ErrorAction SilentlyContinue
$status = if ($pingKali) { "FAIL" } else { "OK" }
Write-Result "Ping Server → Kali ($KALI_IP)" $(if ($pingKali) { "Reachable — segmentation BREACH!" } else { "Timeout — isolation OK" }) $status

# ============================================================
# SECTION 12: WINDOWS UPDATE STATUS
# ============================================================
Write-Section "12. WINDOWS UPDATE STATUS"

$lastUpdate = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
if ($lastUpdate) {
    $daysSince = ((Get-Date) - $lastUpdate.InstalledOn).Days
    $status = if ($daysSince -gt 90) { "FAIL" } elseif ($daysSince -gt 30) { "RISK" } else { "OK" }
    Write-Result "Last update installed" "$($lastUpdate.InstalledOn) ($daysSince days ago)" $status
} else {
    Write-Result "Windows Updates" "No hotfixes found — check manually" "RISK"
}

# ============================================================
# SECTION 13: SMB VERSION (EternalBlue risk)
# ============================================================
Write-Section "13. SMB PROTOCOL VERSION (EternalBlue / MS17-010)"

$smb1 = Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol
$status = if ($smb1.EnableSMB1Protocol) { "FAIL" } else { "OK" }
Write-Result "SMBv1 enabled" $smb1.EnableSMB1Protocol $status

# ============================================================
# SECTION 14: DNS CONFIGURATION
# ============================================================
Write-Section "14. DNS SERVER ROLE CHECK"

$dnsService = Get-Service -Name DNS -ErrorAction SilentlyContinue
if ($dnsService) {
    $status = if ($dnsService.Status -eq "Running") { "OK" } else { "RISK" }
    Write-Result "DNS service status" $dnsService.Status $status
} else {
    Write-Result "DNS service" "Not found — DNS role may not be installed" "RISK"
}

# ============================================================
# FOOTER
# ============================================================
$footer = @"

============================================================
  AUDIT COMPLETE: $DATE
  Log saved to: $LOG
============================================================
  QUICK FILTER COMMANDS:
  Select-String '\[FAIL\]' $LOG
  Select-String '\[RISK\]' $LOG
============================================================
"@
Add-Content $LOG $footer
Write-Host $footer -ForegroundColor Cyan
Write-Host "`n  To review: notepad $LOG" -ForegroundColor White
