# File: Analyze-Kerberoasting-Pattern.ps1

function Detect-KerberoastingPattern {
  param(
    [int]$TimeWindowMinutes = 5,
    [int]$EventThreshold = 3,
    [int]$ServiceThreshold = 2
  )

  $cutoffTime = (Get-Date).AddMinutes(-$TimeWindowMinutes)

  Write-Host "`n=== KERBEROASTING PATTERN ANALYSIS ===" -ForegroundColor Cyan
  Write-Host "Time Window: $TimeWindowMinutes minutes" -ForegroundColor Cyan
  Write-Host "Event Threshold: $EventThreshold" -ForegroundColor Cyan
  Write-Host "Service Threshold: $ServiceThreshold" -ForegroundColor Cyan
  Write-Host "`n"

  try {
    $events = Get-WinEvent -FilterHashtable @{
      LogName = 'Security'
      ID = 4769
      StartTime = $cutoffTime
    } -ErrorAction SilentlyContinue

    if (-not $events) {
      Write-Host "No suspicious events found in last $TimeWindowMinutes minutes" -ForegroundColor Green
      return $null
    }

    # Detailed analysis
    $analysis = @{}

    foreach ($event in $events) {
      # Correct 4769 schema:
      # 0 = TargetUserName, 1 = TargetDomainName, 2 = ServiceName,
      # 3 = ServiceSid, 4 = TicketOptions, 5 = TicketEncryptionType,
      # 6 = IpAddress, 7 = IpPort, 8 = Status, 9 = LogonGuid, 10 = TransmittedServices
      $sourceIP = $event.Properties[6].Value
      $accountName = $event.Properties[0].Value
      $serviceName = try { $event.Properties[2].Value } catch { "Unknown" }

      # IpAddress can come through as "::ffff:172.16.231.x" or even blank for
      # local/loopback-style requests - normalize so grouping doesn't split
      # the same attacker into multiple "different" sources.
      if ([string]::IsNullOrWhiteSpace($sourceIP)) {
        $sourceIP = "(unknown/local)"
      } else {
        $sourceIP = $sourceIP -replace '^::ffff:', ''
      }

      if (-not $analysis[$sourceIP]) {
        $analysis[$sourceIP] = @{
          Events = @()
          Users = @{}
          Services = @{}
          FirstSeen = $event.TimeCreated
          LastSeen = $event.TimeCreated
        }
      }

      $analysis[$sourceIP].Events += $event
      $analysis[$sourceIP].LastSeen = $event.TimeCreated

      if (-not $analysis[$sourceIP].Users[$accountName]) {
        $analysis[$sourceIP].Users[$accountName] = 0
      }
      $analysis[$sourceIP].Users[$accountName]++

      if (-not $analysis[$sourceIP].Services[$serviceName]) {
        $analysis[$sourceIP].Services[$serviceName] = 0
      }
      $analysis[$sourceIP].Services[$serviceName]++
    }

    # Report suspicious sources
    $suspiciousSources = $analysis.Keys |
      Where-Object {
        $analysis[$_].Events.Count -ge $EventThreshold -and
        $analysis[$_].Services.Count -ge $ServiceThreshold
      }

    if ($suspiciousSources) {
      Write-Host "SUSPICIOUS ACTIVITY DETECTED!" -ForegroundColor Red
      Write-Host "`n"

      foreach ($sourceIP in $suspiciousSources) {
        $data = $analysis[$sourceIP]

        Write-Host "Source IP: $sourceIP" -ForegroundColor Red
        Write-Host "Event Count: $($data.Events.Count)" -ForegroundColor Red
        Write-Host "Service Count: $($data.Services.Count)" -ForegroundColor Red
        Write-Host "Time Range: $($data.FirstSeen) -> $($data.LastSeen)" -ForegroundColor Red
        Write-Host "Users:"
        foreach ($user in $data.Users.Keys) {
          Write-Host "  - $user ($($data.Users[$user]) events)" -ForegroundColor Cyan
        }
        Write-Host "Services:"
        foreach ($service in $data.Services.Keys) {
          Write-Host "  - $service ($($data.Services[$service]) events)" -ForegroundColor Cyan
        }
        Write-Host ""
      }

      return $suspiciousSources
    } else {
      # Show what WAS seen even if it didn't cross the threshold - helps
      # you tell "nothing happened" apart from "happened but too small".
      Write-Host "No source crossed the threshold. Raw counts seen:" -ForegroundColor Yellow
      foreach ($sourceIP in $analysis.Keys) {
        $data = $analysis[$sourceIP]
        Write-Host "  $sourceIP -> Events: $($data.Events.Count), Services: $($data.Services.Count)" -ForegroundColor DarkGray
      }
      Write-Host "`nNo kerberoasting patterns detected (above threshold)" -ForegroundColor Green
      return $null
    }

  } catch {
    Write-Host "Error analyzing events: $_" -ForegroundColor Red
    return $null
  }
}

# Run analysis
Detect-KerberoastingPattern -TimeWindowMinutes 5 -EventThreshold 3 -ServiceThreshold 2