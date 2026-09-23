param(
  [int]$CheckInterval = 5,         # 5 seconds check (lower for lab testing)
  [int]$EventThreshold = 3,        # 3+ events = suspicious (adjust for your lab's SPN count)
  [int]$ServiceThreshold = 2,      # 2+ services = suspicious
  [int]$TimeWindowMinutes = 2      # In 2 minutes
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Kerberoasting Real-Time Monitor Started" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Check Interval: $CheckInterval seconds" -ForegroundColor Yellow
Write-Host "Event Threshold: $EventThreshold" -ForegroundColor Yellow
Write-Host "Service Threshold: $ServiceThreshold" -ForegroundColor Yellow
Write-Host "Time Window: $TimeWindowMinutes minutes" -ForegroundColor Yellow

# Sanity check: warn early if auditing isn't even enabled, since that's
# the #1 reason this monitor appears to "never" detect anything.
try {
  $auditCheck = auditpol /get /subcategory:"Kerberos Service Ticket Operations" 2>$null
  if ($auditCheck -match "No Auditing") {
    Write-Host "`n[WARNING] Kerberos Service Ticket Operations auditing looks DISABLED." -ForegroundColor Red
    Write-Host "Event ID 4769 will not be logged until you enable it:" -ForegroundColor Red
    Write-Host '  auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable' -ForegroundColor Yellow
  }
} catch {
  Write-Host "`n[INFO] Could not verify audit policy automatically. Run auditpol manually to confirm." -ForegroundColor DarkYellow
}

Write-Host "`n"

$alertCount = 0
$lastAlertTime = $null

while ($true) {
  $cutoffTime = (Get-Date).AddMinutes(-$TimeWindowMinutes)

  # Get TGS-REQ events (Event ID 4769)
  try {
    $events = Get-WinEvent -FilterHashtable @{
      LogName = 'Security'
      ID = 4769
      StartTime = $cutoffTime
    } -ErrorAction SilentlyContinue

    if ($events) {
      # Group by Source IP
      $grouped = @()

      # Correct 4769 schema: Properties[6] = IpAddress (source), Properties[2] = ServiceName
      if ($events -is [array]) {
        $grouped = $events | Group-Object -Property {$_.Properties[6].Value}
      } else {
        $grouped = @($events) | Group-Object -Property {$_.Properties[6].Value}
      }

      # Analyze each source IP
      foreach ($group in $grouped) {
        $sourceIP = $group.Name
        $eventCount = $group.Count

        # Count unique services
        $services = $group.Group |
          ForEach-Object {
            try {
              $_.Properties[2].Value
            } catch {
              "Unknown"
            }
          } |
          Get-Unique

        $serviceCount = $services.Count

        # Count unique users
        $users = $group.Group |
          ForEach-Object {
            try {
              $_.Properties[0].Value
            } catch {
              "Unknown"
            }
          } |
          Get-Unique

        # Check thresholds
        if ($eventCount -ge $EventThreshold -and $serviceCount -ge $ServiceThreshold) {
          $alertCount++
          $lastAlertTime = Get-Date

          Write-Host "`n" -ForegroundColor Red
          Write-Host "================================================================" -ForegroundColor Red
          Write-Host "           KERBEROASTING DETECTED!                            " -ForegroundColor Red
          Write-Host "================================================================" -ForegroundColor Red

          Write-Host "`n[ALERT #$alertCount] $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Red

          Write-Host "`nSOURCE INFORMATION:" -ForegroundColor Yellow
          Write-Host "  Source IP: $sourceIP" -ForegroundColor Red
          Write-Host "  Total Events: $eventCount (Threshold: $EventThreshold)" -ForegroundColor Red
          Write-Host "  Unique Services: $serviceCount (Threshold: $ServiceThreshold)" -ForegroundColor Red

          Write-Host "`nUSER INFORMATION:" -ForegroundColor Yellow
          Write-Host "  Users: $($users -join ', ')" -ForegroundColor Cyan

          Write-Host "`nTARGETED SERVICES:" -ForegroundColor Yellow
          $services | ForEach-Object {
            Write-Host "  - $_" -ForegroundColor Cyan
          }

          Write-Host "`nTIMELINE (Last 5 events):" -ForegroundColor Yellow
          $group.Group | Sort-Object TimeCreated -Descending | Select-Object -First 5 |
            ForEach-Object {
              $time = $_.TimeCreated.ToString('HH:mm:ss')
              $service = try { $_.Properties[2].Value } catch { "Unknown" }
              Write-Host "  $time - $service" -ForegroundColor Cyan
            }

          Write-Host "`nRISK ASSESSMENT:" -ForegroundColor Yellow
          if ($eventCount -gt 50 -and $serviceCount -gt 10) {
            Write-Host "  Severity: CRITICAL" -ForegroundColor Red
            Write-Host "  Confidence: 99% - DEFINITE ATTACK" -ForegroundColor Red
          } elseif ($eventCount -gt 30 -and $serviceCount -gt 5) {
            Write-Host "  Severity: HIGH" -ForegroundColor Yellow
            Write-Host "  Confidence: 95% - LIKELY ATTACK" -ForegroundColor Yellow
          } elseif ($eventCount -ge $EventThreshold -and $serviceCount -ge $ServiceThreshold) {
            Write-Host "  Severity: MEDIUM" -ForegroundColor Yellow
            Write-Host "  Confidence: 80% - POSSIBLE ATTACK" -ForegroundColor Yellow
          }

          Write-Host "`nRECOMMENDED ACTIONS:" -ForegroundColor Yellow
          Write-Host "  1. Block source IP immediately" -ForegroundColor Green
          Write-Host "  2. Reset service account passwords" -ForegroundColor Green
          Write-Host "  3. Check for lateral movement" -ForegroundColor Green
          Write-Host "  4. Investigate source workstation" -ForegroundColor Green
          Write-Host "  5. Review historical logs" -ForegroundColor Green

          Write-Host "`n" -ForegroundColor Red
        }
      }
    }
  } catch {
    Write-Host "Error: $_" -ForegroundColor Red
  }

  # Heartbeat every poll, so you can see the monitor is actually alive
  $eventsSeenThisPoll = if ($events) { @($events).Count } else { 0 }
  Write-Host "$(Get-Date -Format 'HH:mm:ss') - Poll complete. 4769 events in window: $eventsSeenThisPoll | Alerts so far: $alertCount" -ForegroundColor DarkGray

  Start-Sleep -Seconds $CheckInterval
}