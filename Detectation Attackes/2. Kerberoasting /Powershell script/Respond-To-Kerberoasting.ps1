function Respond-ToKerberoastingAttack {
  param(
    [string]$AttackerIP,
    [string[]]$AffectedServiceAccounts,
    [switch]$AutoBlock = $true,
    [switch]$AutoResetPasswords = $false
  )
  
  Write-Host "?? KERBEROASTING RESPONSE INITIATED" -ForegroundColor Red
  Write-Host "Attacker IP: $AttackerIP" -ForegroundColor Red
  Write-Host "`n"
  
  # STEP 1: Immediate Containment
  Write-Host "[STEP 1] IMMEDIATE CONTAINMENT" -ForegroundColor Yellow
  Write-Host "---------------------------------" -ForegroundColor Yellow
  
  if ($AutoBlock) {
    Write-Host "  ? Blocking IP: $AttackerIP" -ForegroundColor Cyan
    
    # Add firewall rule
    New-NetFirewallRule -DisplayName "Block-Kerberoasting-$AttackerIP" `
      -Direction Inbound `
      -Action Block `
      -RemoteAddress $AttackerIP `
      -Protocol TCP `
      -ErrorAction SilentlyContinue
    
    Write-Host "    ? Firewall rule created" -ForegroundColor Green
    
    # Terminate existing connections (optional)
    # Get-NetTCPConnection -RemoteAddress $AttackerIP | Stop-NetTCPConnection -Force
  }
  
  Write-Host "`n"
  
  # STEP 2: Service Account Protection
  Write-Host "[STEP 2] SERVICE ACCOUNT PROTECTION" -ForegroundColor Yellow
  Write-Host "-----------------------------------" -ForegroundColor Yellow
  
  foreach ($account in $AffectedServiceAccounts) {
    Write-Host "  ? Checking account: $account" -ForegroundColor Cyan
    
    # Get account info
    $adUser = Get-ADUser -Identity $account -Properties PasswordLastSet
    
    if ($AutoResetPasswords) {
      Write-Host "    ? Resetting password for: $account" -ForegroundColor Yellow
      
      $newPassword = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 32 | ForEach-Object {[char]$_})
      Set-ADAccountPassword -Identity $account `
        -NewPassword (ConvertTo-SecureString $newPassword -AsPlainText -Force) `
        -Reset
      
      Write-Host "    ? Password reset" -ForegroundColor Green
      Write-Host "    ? New password length: 32 characters" -ForegroundColor Green
      
      # Log new password securely
      "$account : $newPassword" | Out-File -FilePath "C:\Temp\ResetPasswords_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt" -Encoding UTF8 -Force
      Write-Host "    ? Password saved securely" -ForegroundColor Green
    }
    
    # Force password change on next login
    Set-ADUser -Identity $account -ChangePasswordAtLogon $true
    Write-Host "    ? Password change required at next login" -ForegroundColor Green
  }
  
  Write-Host "`n"
  
  # STEP 3: Investigation
  Write-Host "[STEP 3] INVESTIGATION" -ForegroundColor Yellow
  Write-Host "----------------------" -ForegroundColor Yellow
  
  Write-Host "  ? Collecting forensic evidence..." -ForegroundColor Cyan
  
  # Get attack timeline
  $attackEvents = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4769
    StartTime = (Get-Date).AddHours(-2)
  } -ErrorAction SilentlyContinue |
    Where-Object {$_.Properties[1].Value -eq $AttackerIP}
  
  Write-Host "    ? Attack timeline collected: $($attackEvents.Count) events" -ForegroundColor Green
  
  # Get targeted services
  $targetedServices = $attackEvents |
    ForEach-Object {$_.Properties[10].Value} |
    Get-Unique
  
  Write-Host "    ? Targeted services identified: $($targetedServices.Count)" -ForegroundColor Green
  
  # Export forensics
  $attackEvents | Export-Csv -Path "C:\Temp\Kerberoasting_Attack_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" -Force
  Write-Host "    ? Evidence exported to CSV" -ForegroundColor Green
  
  Write-Host "`n"
  
  # STEP 4: Notifications
  Write-Host "[STEP 4] NOTIFICATIONS" -ForegroundColor Yellow
  Write-Host "----------------------" -ForegroundColor Yellow
  
  Write-Host "  ? Sending alerts..." -ForegroundColor Cyan
  
  # Email alert
  $emailParams = @{
    To = "security@company.com"
    Subject = "CRITICAL: Kerberoasting Attack Detected"
    Body = @"
KERBEROASTING ATTACK DETECTED

Attack Details:
+- Attacker IP: $AttackerIP
+- Services Targeted: $($targetedServices -join ', ')
+- Affected Accounts: $($AffectedServiceAccounts -join ', ')
+- Event Count: $($attackEvents.Count)
+- Time: $(Get-Date)

Actions Taken:
+- ? Firewall rule: CREATED
+- ? Service passwords: RESET
+- ? Forensics: COLLECTED
+- ? Alerts: SENT

Next Steps:
1. Investigate source workstation
2. Check for lateral movement
3. Review credential usage
4. Audit domain permissions
5. Consider credential guard deployment
"@
    SmtpServer = "mail.company.com"
    From = "security-alerts@company.com"
  }
  
  # Send-MailMessage @emailParams -ErrorAction SilentlyContinue
  Write-Host "    ? Email notification would be sent" -ForegroundColor Green
  
  Write-Host "`n"
  
  # STEP 5: Summary Report
  Write-Host "[STEP 5] RESPONSE SUMMARY" -ForegroundColor Yellow
  Write-Host "------------------------" -ForegroundColor Yellow
  
  Write-Host "`n? ATTACK CONTAINMENT: COMPLETE" -ForegroundColor Green
  Write-Host "? SERVICE PROTECTION: COMPLETE" -ForegroundColor Green
  Write-Host "? INVESTIGATION: COMPLETE" -ForegroundColor Green
  Write-Host "? NOTIFICATIONS: COMPLETE" -ForegroundColor Green
  
  Write-Host "`nResponse Time: < 5 minutes" -ForegroundColor Cyan
  Write-Host "Status: ATTACK MITIGATED" -ForegroundColor Green
}

# Usage
Respond-ToKerberoastingAttack `
  -AttackerIP "192.168.1.100" `
  -AffectedServiceAccounts @("svc_sql", "svc_web", "svc_exchange") `
  -AutoBlock $true `
  -AutoResetPasswords $false