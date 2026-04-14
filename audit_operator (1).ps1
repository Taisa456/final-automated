# ============================================================
#  AUDIT — OPERATOR MACHINE (Windows 10/11)
#  Run as Administrator on the Operator Machine
#  Output saved to C:\audit_operator.txt
#
#  Usage: Right-click PowerShell -> "Run as Administrator"
#         Set-ExecutionPolicy Bypass -Scope Process -Force
#         .\audit_operator.ps1
# ============================================================

$LOG = "C:\audit_operator.txt"
$DATE = Get-Date -Format "yyyy-MM-dd HH:mm"

# --- FILL IN IP ADDRESSES BEFORE RUNNING ---
$SERVER_IP = "192.168.X.X"   # Main Server
$META_IP   = "192.168.X.X"   # Metasploitable 2
$KALI_IP   = "192.168.X.X"   # Kali Linux (attacker)
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

$header = @"
============================================================
  SECURITY AUDIT — OPERATOR MACHINE (Windows 10/11)
  Date: $DATE
============================================================
"@
Set-Content $LOG $header
Write-Host $header -ForegroundColor White

# ============================================================
# SECTION 1: DOMAIN MEMBERSHIP
# ============================================================
Write-Section "1. DOMAIN MEMBERSHIP (machine should be joined to domain)"

$cs = Get-ComputerInfo | Select-Object CsDomain, CsPartOfDomain
$inDomain = $cs.CsPartOfDomain
$status = if ($inDomain) { "OK" } else { "FAIL" }
Write-Result "Domain joined" $cs.CsDomain $status

# ============================================================
# SECTION 2: LOCAL ADMINISTRATOR GROUP (domain user must NOT be admin)
# ============================================================
Write-Section "2. LOCAL ADMINISTRATOR RIGHTS (domain user must not be in Admins)"

$localAdmins = net localgroup Administrators 2>&1
Add-Content $LOG "  Members of local Administrators group:"
$localAdmins | ForEach-Object {
    $line = "    $_"
    $isDomainUser = ($_ -match "\\") -and ($_ -notmatch "BUILTIN|NT AUTHORITY|Administrator")
    $color = if ($isDomainUser) { "Yellow" } else { "White" }
    Write-Host $line -ForegroundColor $color
    Add-Content $LOG $line
    if ($isDomainUser) {
        $risk = "    [RISK] Domain user '$_' has local administrator rights!"
        Write-Host $risk -ForegroundColor Red
        Add-Content $LOG $risk
    }
}

# ============================================================
# SECTION 3: RDP CONFIGURATION AND NLA (critical!)
# ============================================================
Write-Section "3. RDP SETTINGS AND NLA (NLA must be DISABLED per project spec)"

# RDP enabled check
$rdpEnabled = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections").fDenyTSConnections
$rdpStatus  = if ($rdpEnabled -eq 0) { "OK" } else { "FAIL" }
Write-Result "RDP enabled" $(if ($rdpEnabled -eq 0) { "Yes" } else { "No" }) $rdpStatus

# NLA check — per project spec, NLA should be OFF (intentional vulnerability)
$nlaEnabled = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue).UserAuthentication
$nlaStatus  = if ($nlaEnabled -eq 0) { "RISK" } else { "OK" }
$nlaText    = if ($nlaEnabled -eq 0) { "DISABLED — NLA vulnerability present (expected for audit)" } else { "Enabled — NLA active" }
Write-Result "NLA (Network Level Authentication)" $nlaText $nlaStatus

# RDP port
$rdpPort   = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "PortNumber").PortNumber
$portStatus = if ($rdpPort -ne 3389) { "RISK" } else { "" }
Write-Result "RDP port" $rdpPort $portStatus

# ============================================================
# SECTION 4: SAVED RDP CREDENTIALS
# ============================================================
Write-Section "4. SAVED RDP CREDENTIALS (cmdkey)"

$creds = cmdkey /list 2>&1
Add-Content $LOG "  Saved credentials:"
$creds | ForEach-Object {
    $line = "    $_"
    $isRisky = ($_ -match "Target|User") -and ($_ -notmatch "No|none")
    $color = if ($isRisky) { "Yellow" } else { "White" }
    Write-Host $line -ForegroundColor $color
    Add-Content $LOG $line
}
$hasCredentials = $creds | Where-Object { $_ -match "Target:" }
if ($hasCredentials) {
    Write-Result "Saved RDP passwords" "Found! Risk of credential theft" "RISK"
} else {
    Write-Result "Saved RDP passwords" "None detected" "OK"
}

# ============================================================
# SECTION 5: SMB SHARED FOLDERS
# ============================================================
Write-Section "5. SMB SHARED FOLDERS (net share)"

$shares = net share 2>&1
Add-Content $LOG "  Shared folders:"
$shares | ForEach-Object {
    $line = "    $_"
    $isRisky = ($_ -match "Everyone|Guest|C\$|ADMIN\$") -and ($_ -notmatch "^-")
    $color = if ($isRisky) { "Yellow" } else { "White" }
    Write-Host $line -ForegroundColor $color
    Add-Content $LOG $line
}

# ============================================================
# SECTION 6: INTERNET ISOLATION (Operator must have NO internet)
# ============================================================
Write-Section "6. INTERNET ISOLATION (Operator must NOT have internet access)"

Add-Content $LOG "  Attempting to reach external addresses..."
$targets = @("8.8.8.8", "1.1.1.1", "google.com")
foreach ($target in $targets) {
    $ping   = Test-Connection -ComputerName $target -Count 2 -Quiet -ErrorAction SilentlyContinue
    $status = if ($ping) { "FAIL" } else { "OK" }
    $text   = if ($ping) { "Reachable — internet NOT isolated!" } else { "Timeout — isolation OK" }
    Write-Result "Ping $target" $text $status
}

# ============================================================
# SECTION 7: LLMNR AND NETBIOS (Responder hash interception risk)
# ============================================================
Write-Section "7. LLMNR AND NETBIOS (risk: Responder hash capture)"

$llmnr = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue).EnableMulticast
if ($llmnr -eq 0) {
    Write-Result "LLMNR" "Disabled" "OK"
} else {
    Write-Result "LLMNR" "ENABLED — vulnerable to Responder attack!" "RISK"
}

$adapts = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled }
foreach ($a in $adapts) {
    $netbios = $a.TcpipNetbiosOptions
    $netbiosText = switch ($netbios) {
        0 { "Default (follows DHCP)" }
        1 { "Enabled" }
        2 { "Disabled" }
        default { "Unknown" }
    }
    $status = if ($netbios -eq 2) { "OK" } else { "RISK" }
    Write-Result "NetBIOS on $($a.Description)" $netbiosText $status
}

# ============================================================
# SECTION 8: WINDOWS UPDATE STATUS
# ============================================================
Write-Section "8. WINDOWS UPDATE STATUS"

$lastUpdate = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
if ($lastUpdate) {
    $daysSince = ((Get-Date) - $lastUpdate.InstalledOn).Days
    $status    = if ($daysSince -gt 90) { "FAIL" } elseif ($daysSince -gt 30) { "RISK" } else { "OK" }
    Write-Result "Last update installed" "$($lastUpdate.InstalledOn) ($daysSince days ago)" $status
} else {
    Write-Result "Windows Updates" "No hotfixes found — check manually" "RISK"
}

# ============================================================
# SECTION 9: SUSPICIOUS INSTALLED SOFTWARE
# ============================================================
Write-Section "9. SUSPICIOUS INSTALLED SOFTWARE (non-work applications)"

$allApps = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue |
           Select-Object DisplayName, DisplayVersion |
           Where-Object { $_.DisplayName }

$suspiciousKeywords = @("torrent","game","steam","discord","vlc","utorrent","bittorrent","minecraft","epic games")
Add-Content $LOG "`n  Potentially unwanted software:"
$found = $false
foreach ($app in $allApps) {
    foreach ($kw in $suspiciousKeywords) {
        if ($app.DisplayName -match $kw) {
            $line = "    [RISK] $($app.DisplayName) $($app.DisplayVersion)"
            Write-Host $line -ForegroundColor Yellow
            Add-Content $LOG $line
            $found = $true
        }
    }
}
if (-not $found) {
    Write-Result "Suspicious software" "None detected" "OK"
}

# ============================================================
# SECTION 10: STICKY KEYS BACKDOOR (Shift x5 at login screen)
# ============================================================
Write-Section "10. STICKY KEYS BACKDOOR CHECK (sethc.exe replaced with cmd.exe?)"

$stickyPath = "C:\Windows\System32\sethc.exe"
$cmdPath    = "C:\Windows\System32\cmd.exe"
$stickyHash = (Get-FileHash $stickyPath -Algorithm MD5 -ErrorAction SilentlyContinue).Hash
$cmdHash    = (Get-FileHash $cmdPath    -Algorithm MD5 -ErrorAction SilentlyContinue).Hash
if ($stickyHash -eq $cmdHash) {
    Write-Result "Sticky Keys backdoor" "sethc.exe has been replaced with cmd.exe!" "FAIL"
} else {
    Write-Result "Sticky Keys backdoor" "Not detected" "OK"
}

# ============================================================
# SECTION 11: LOGON AUDIT / FAILED LOGIN EVENTS
# ============================================================
Write-Section "11. LOGON AUDIT — FAILED LOGIN EVENTS"

$failEvents = Get-EventLog -LogName Security -EntryType FailureAudit -Newest 10 -ErrorAction SilentlyContinue
if ($failEvents) {
    Write-Result "Failed logon attempts (last 10)" "$($failEvents.Count) found" "OK"
    $failEvents | Select-Object TimeGenerated, Message | ForEach-Object {
        $shortMsg = ($_.Message -split "`n")[0]
        Add-Content $LOG "    $($_.TimeGenerated) — $shortMsg"
    }
} else {
    Write-Result "Failed logon audit" "No records — audit may be disabled" "RISK"
}

# ============================================================
# SECTION 12: NETWORK REACHABILITY FROM OPERATOR
# ============================================================
Write-Section "12. NETWORK REACHABILITY CHECKS (from Operator)"

# Should reach Main Server
$pingServer = Test-Connection -ComputerName $SERVER_IP -Count 2 -Quiet -ErrorAction SilentlyContinue
$status = if ($pingServer) { "OK" } else { "FAIL" }
Write-Result "Ping Operator → Main Server ($SERVER_IP)" $(if ($pingServer) { "Reachable" } else { "Unreachable" }) $status

# Should reach Metasploitable
$pingMeta = Test-Connection -ComputerName $META_IP -Count 2 -Quiet -ErrorAction SilentlyContinue
$status = if ($pingMeta) { "OK" } else { "FAIL" }
Write-Result "Ping Operator → Metasploitable ($META_IP)" $(if ($pingMeta) { "Reachable" } else { "Unreachable" }) $status

# Must NOT reach Kali
$pingKali = Test-Connection -ComputerName $KALI_IP -Count 2 -Quiet -ErrorAction SilentlyContinue
$status = if ($pingKali) { "FAIL" } else { "OK" }
Write-Result "Ping Operator → Kali ($KALI_IP)" $(if ($pingKali) { "Reachable — segmentation BREACH!" } else { "Timeout — isolation OK" }) $status

# ============================================================
# SECTION 13: SMB VERSION (EternalBlue risk)
# ============================================================
Write-Section "13. SMB PROTOCOL VERSION (EternalBlue / MS17-010)"

try {
    $smb1 = Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol
    $status = if ($smb1.EnableSMB1Protocol) { "FAIL" } else { "OK" }
    Write-Result "SMBv1 enabled" $smb1.EnableSMB1Protocol $status
} catch {
    Write-Result "SMB check" $_.Exception.Message "FAIL"
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
