# ================================================
# CIS Audit Script - lab.local
# Windows Server 2022 / Active Directory
# Version: 3.0 - Production Ready
# ================================================
# This script verifies CIS Benchmark compliance
# across all hardening categories applied via GPO.
# It produces a color-coded console report and
# exports results to C:\Scripts\audit-report.txt
# ================================================

$results = [System.Collections.Generic.List[PSCustomObject]]::new()
$date = Get-Date -Format "dd/MM/yyyy HH:mm"

function Add-Check {
    param(
        [string]$Category,
        [string]$Description,
        [bool]$Passed,
        [string]$Expected,
        [string]$Found
    )
    $results.Add([PSCustomObject]@{
        Category    = $Category
        Description = $Description
        Status      = if ($Passed) { "PASS" } else { "FAIL" }
        Expected    = $Expected
        Found       = $Found
    })
}

# ================================================
# 1. NETWORK SECURITY
# ================================================

# SMBv1 — EternalBlue / WannaCry exploit vector
try {
    $smb = (Get-SmbServerConfiguration).EnableSMB1Protocol
    Add-Check "Network" "SMBv1 disabled" ($smb -eq $false) "False" "$smb"
} catch {
    Add-Check "Network" "SMBv1 disabled" $false "False" "Error reading"
}

# LLMNR — Responder poisoning attack vector
try {
    $llmnr = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -ErrorAction Stop).EnableMulticast
    Add-Check "Network" "LLMNR disabled" ($llmnr -eq 0) "0" "$llmnr"
} catch {
    Add-Check "Network" "LLMNR disabled" $false "0" "Key not found"
}

# USB Storage — Physical data exfiltration
try {
    $usb = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -ErrorAction Stop).Start
    Add-Check "Network" "USB Storage blocked" ($usb -eq 4) "4" "$usb"
} catch {
    Add-Check "Network" "USB Storage blocked" $false "4" "Key not found"
}

# RDP NLA — Requires authentication before session opens
try {
    $rdp = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -ErrorAction Stop).UserAuthentication
    Add-Check "Network" "RDP NLA enabled" ($rdp -eq 1) "1" "$rdp"
} catch {
    Add-Check "Network" "RDP NLA enabled" $false "1" "Key not found"
}

# ================================================
# 2. PASSWORD POLICY
# ================================================

try {
    $pp = Get-ADDefaultDomainPasswordPolicy

    # Minimum 14 characters — brute force resistance
    Add-Check "Password" "Min length >= 14" ($pp.MinPasswordLength -ge 14) ">=14" "$($pp.MinPasswordLength)"

    # Complexity — prevents simple passwords
    Add-Check "Password" "Complexity enabled" ($pp.ComplexityEnabled -eq $true) "True" "$($pp.ComplexityEnabled)"

    # History — prevents password reuse
    Add-Check "Password" "History >= 24" ($pp.PasswordHistoryCount -ge 24) ">=24" "$($pp.PasswordHistoryCount)"

    # Max age — forces regular rotation
    Add-Check "Password" "Max age <= 60 days" ($pp.MaxPasswordAge.TotalDays -le 60) "<=60" "$([math]::Round($pp.MaxPasswordAge.TotalDays))"

    # Min age — prevents immediate password change back
    Add-Check "Password" "Min age >= 1 day" ($pp.MinPasswordAge.TotalDays -ge 1) ">=1" "$([math]::Round($pp.MinPasswordAge.TotalDays))"

} catch {
    Add-Check "Password" "Password policy" $false "N/A" "AD Error"
}

# ================================================
# 3. ACCOUNT LOCKOUT
# ================================================

try {
    # Threshold — blocks brute force after 5 attempts
    Add-Check "Lockout" "Threshold <= 5" ($pp.LockoutThreshold -le 5 -and $pp.LockoutThreshold -gt 0) "1-5" "$($pp.LockoutThreshold)"

    # Duration — slows down attackers
    Add-Check "Lockout" "Duration >= 15 min" ($pp.LockoutDuration.TotalMinutes -ge 15) ">=15" "$($pp.LockoutDuration.TotalMinutes)"

    # Reset counter — observation window
    Add-Check "Lockout" "Reset counter >= 15 min" ($pp.LockoutObservationWindow.TotalMinutes -ge 15) ">=15" "$($pp.LockoutObservationWindow.TotalMinutes)"

} catch {
    Add-Check "Lockout" "Lockout policy" $false "N/A" "AD Error"
}

# ================================================
# 4. FIREWALL
# ================================================

try {
    $fwD  = Get-NetFirewallProfile -Profile Domain
    $fwPr = Get-NetFirewallProfile -Profile Private
    $fwPu = Get-NetFirewallProfile -Profile Public

    Add-Check "Firewall" "Domain profile ON"  ($fwD.Enabled  -eq $true) "True" "$($fwD.Enabled)"
    Add-Check "Firewall" "Private profile ON" ($fwPr.Enabled -eq $true) "True" "$($fwPr.Enabled)"
    Add-Check "Firewall" "Public profile ON"  ($fwPu.Enabled -eq $true) "True" "$($fwPu.Enabled)"
    Add-Check "Firewall" "Domain inbound blocked" ($fwD.DefaultInboundAction -eq "Block") "Block" "$($fwD.DefaultInboundAction)"

} catch {
    Add-Check "Firewall" "Firewall profiles" $false "N/A" "Error reading"
}

# ================================================
# 5. SERVICES
# ================================================

# Print Spooler — PrintNightmare CVE-2021-34527
try {
    $spooler = Get-Service -Name "Spooler" -ErrorAction Stop
    Add-Check "Services" "Print Spooler disabled" ($spooler.StartType -eq "Disabled") "Disabled" "$($spooler.StartType)"
} catch {
    Add-Check "Services" "Print Spooler disabled" $false "Disabled" "Service not found"
}

# Remote Registry — remote configuration access
try {
    $remReg = Get-Service -Name "RemoteRegistry" -ErrorAction Stop
    Add-Check "Services" "Remote Registry disabled" ($remReg.StartType -eq "Disabled") "Disabled" "$($remReg.StartType)"
} catch {
    Add-Check "Services" "Remote Registry disabled" $false "Disabled" "Service not found"
}

# AppLocker — application whitelisting
try {
    $appID = Get-Service -Name "AppIDSvc" -ErrorAction Stop
    Add-Check "Services" "AppLocker (AppIDSvc) running" ($appID.Status -eq "Running") "Running" "$($appID.Status)"
} catch {
    Add-Check "Services" "AppLocker running" $false "Running" "Service not found"
}

# ================================================
# 6. ACCOUNTS
# ================================================

# Guest account — eliminates anonymous access
try {
    $guest = Get-ADUser -Filter { SamAccountName -eq "Guest" } -Properties Enabled
    Add-Check "Accounts" "Guest account disabled" ($guest.Enabled -eq $false) "False" "$($guest.Enabled)"
} catch {
    Add-Check "Accounts" "Guest account disabled" $false "False" "AD Error"
}

# Domain Admins — least privilege
try {
    $admins = Get-ADGroupMember -Identity "Domain Admins" -ErrorAction Stop
    $adminCount = ($admins | Measure-Object).Count
    Add-Check "Accounts" "Domain Admins count <= 2" ($adminCount -le 2) "<=2" "$adminCount member(s)"
} catch {
    Add-Check "Accounts" "Domain Admins count" $false "<=2" "AD Error"
}

# ================================================
# 7. AUTHENTICATION
# ================================================

# NTLMv2 — blocks hash downgrade attacks
try {
    $lsa = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction Stop
    Add-Check "Auth" "NTLMv2 only (level >= 5)" ($lsa.LmCompatibilityLevel -ge 5) ">=5" "$($lsa.LmCompatibilityLevel)"
} catch {
    Add-Check "Auth" "NTLMv2 level" $false ">=5" "Key not found"
}

# WDigest — blocks Mimikatz plaintext extraction
try {
    $wdigest = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -ErrorAction Stop
    Add-Check "Auth" "WDigest disabled" ($wdigest.UseLogonCredential -eq 0) "0" "$($wdigest.UseLogonCredential)"
} catch {
    Add-Check "Auth" "WDigest disabled" $false "0" "Key not found"
}

# RDP NLA — checked in Network section above

# ================================================
# 8. ENCRYPTION
# ================================================

# BitLocker — full disk encryption AES-256
try {
    $bl = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop
    Add-Check "Encryption" "BitLocker C: active" ($bl.ProtectionStatus -eq "On") "On" "$($bl.ProtectionStatus)"
} catch {
    Add-Check "Encryption" "BitLocker C: active" $false "On" "Error reading"
}

# ================================================
# 9. APPLOCKER
# ================================================

# AppLocker deny rules — blocks malware execution from Downloads + Temp
try {
    $policy = Get-AppLockerPolicy -Effective -ErrorAction Stop
    $denyRules = $policy.RuleCollections | ForEach-Object { $_ } | Where-Object { $_.Action -eq "Deny" }
    Add-Check "AppLocker" "Deny rules configured" ($denyRules.Count -gt 0) ">0 deny rules" "$($denyRules.Count) rule(s)"
} catch {
    Add-Check "AppLocker" "AppLocker policy" $false "N/A" "Error reading"
}

# ================================================
# REPORT OUTPUT
# ================================================

$passed = ($results | Where-Object { $_.Status -eq "PASS" }).Count
$failed = ($results | Where-Object { $_.Status -eq "FAIL" }).Count
$total  = $results.Count
$pct    = [math]::Round(($passed / $total) * 100)

$scoreColor = if ($pct -ge 80) { "Green" } elseif ($pct -ge 60) { "Yellow" } else { "Red" }

Write-Host ""
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "   CIS AUDIT REPORT - $date" -ForegroundColor Cyan
Write-Host "   Score: $passed / $total ($pct%)" -ForegroundColor $scoreColor
Write-Host "===================================================" -ForegroundColor Cyan

$currentCat = ""
foreach ($r in $results) {
    if ($r.Category -ne $currentCat) {
        Write-Host ""
        Write-Host "[ $($r.Category) ]" -ForegroundColor Magenta
        $currentCat = $r.Category
    }
    if ($r.Status -eq "PASS") {
        Write-Host "  [PASS] $($r.Description) - Found: $($r.Found)" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] $($r.Description) - Expected: $($r.Expected) | Found: $($r.Found)" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host ""

# Export to text file
$lines = @()
$lines += "CIS AUDIT REPORT - $date"
$lines += "Score: $passed/$total ($pct%)"
$lines += "=" * 50
$currentCat = ""
foreach ($r in $results) {
    if ($r.Category -ne $currentCat) {
        $lines += ""
        $lines += "[ $($r.Category) ]"
        $currentCat = $r.Category
    }
    $status = if ($r.Status -eq "PASS") { "[PASS]" } else { "[FAIL]" }
    $lines += "  $status $($r.Description) | Expected: $($r.Expected) | Found: $($r.Found)"
}

$lines | Out-File "C:\Scripts\audit-report.txt" -Encoding UTF8
Write-Host "Report saved: C:\Scripts\audit-report.txt" -ForegroundColor Cyan
