$ErrorActionPreference = "Stop"

$Prefix  = "http://+:8765/"
$LogPath = "C:\ProgramData\SimRunner\simrunner.log"
$AllowedSim = @("pwsh_suspicious_flags","cmd_to_pwsh_chain")

# Ensure log exists
if (!(Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Force (Split-Path $LogPath) | Out-Null }
if (!(Test-Path $LogPath)) { New-Item -ItemType File -Force $LogPath | Out-Null }

function Write-LogLine([string]$line) {
  try {
    $fs = [System.IO.File]::Open($LogPath,[System.IO.FileMode]::Append,[System.IO.FileAccess]::Write,[System.IO.FileShare]::ReadWrite)
    $sw = New-Object System.IO.StreamWriter($fs,[Text.Encoding]::UTF8)
    $sw.WriteLine($line); $sw.Flush()
    $sw.Dispose(); $fs.Dispose()
  } catch {}
}

function Send-Json($res, $obj, $code=200) {
  $payload = $obj | ConvertTo-Json -Compress
  $bytes = [Text.Encoding]::UTF8.GetBytes($payload)
  $res.StatusCode = $code
  $res.ContentType = "application/json"
  $res.ContentLength64 = $bytes.Length
  $res.OutputStream.Write($bytes,0,$bytes.Length)
  $res.OutputStream.Close()
  $res.Close()
}

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add($Prefix)
$listener.Start()
Write-Host "SimRunner listening on http://+:8765/ (POST /run)" -ForegroundColor Green

while ($true) {
  $ctx = $listener.GetContext()
  $req = $ctx.Request
  $res = $ctx.Response

  if ($req.HttpMethod -ne "POST" -or $req.Url.AbsolutePath -ne "/run") {
    Send-Json $res @{ ok=$false; error="not found" } 404
    continue
  }

  $sr = New-Object System.IO.StreamReader($req.InputStream, $req.ContentEncoding)
  $body = $sr.ReadToEnd()
  $sr.Close()

  try { $json = $body | ConvertFrom-Json } catch {
    Send-Json $res @{ ok=$false; error="bad json" } 400
    continue
  }

  # ---------------- Atomic actions ----------------
  $action = ""
  if ($json.PSObject.Properties.Name -contains "action") { $action = [string]$json.action }

  if ($action -eq "setup_atomic") {
    Start-Process powershell.exe -WindowStyle Hidden -ArgumentList @(
      "-NoProfile","-ExecutionPolicy","Bypass","-Command",
      "IEX (Invoke-WebRequest 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing); Install-AtomicRedTeam -getAtomics -Force"
    ) | Out-Null

    Send-Json $res @{ ok=$true; action="setup_atomic"; status="started" } 200
    continue
  }

  if ($action -eq "run_atomic") {
    $tech = [string]$json.technique
    $test = [int]$json.test

    # basic input safety
    if ($tech -notmatch '^T\d{4}(\.\d{3})?$' -or $test -lt 1 -or $test -gt 999) {
      Send-Json $res @{ ok=$false; error="bad technique/test" } 400
      continue
    }

    $cmd = @"
`$ErrorActionPreference='Stop'
Import-Module 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1' -Force
Invoke-AtomicTest '$tech' -TestNumbers $test -Confirm:`$false
Write-EventLog -LogName Application -Source 'WazuhSim' -EntryType Information -EventId 2000 -Message "ATOMIC_RUN technique=$tech test=$test"
"@

    Start-Process powershell.exe -WindowStyle Hidden -ArgumentList @(
      "-NoProfile","-ExecutionPolicy","Bypass","-Command",$cmd
    ) | Out-Null

    Send-Json $res @{ ok=$true; action="run_atomic"; technique=$tech; test=$test } 200
    continue
  }
  # -------------- end Atomic actions --------------

  # Backwards-compatible simulation_id handling
  $sim = ""
  if ($json.PSObject.Properties.Name -contains "simulation_id") { $sim = [string]$json.simulation_id }

  if (-not ($AllowedSim -contains $sim)) {
    Send-Json $res @{ ok=$false; error="simulation not allowed" } 403
    continue
  }

  # ACK immediately
  $ts = (Get-Date).ToUniversalTime().ToString("o") + "Z"
  Send-Json $res @{ ok=$true; simulation_id=$sim; marker=("SIMULATION_RUN id=$sim ts=$ts status=accepted") } 200

  # Run simulation async
  $cmd = @"
`$ErrorActionPreference='Stop'
try {
  `$ts = (Get-Date).ToUniversalTime().ToString('o') + 'Z'
  Add-Content -Path '$LogPath' -Value ('SIMULATION_RUN id=$sim ts=' + `$ts + ' status=starting')

  if ('$sim' -eq 'pwsh_suspicious_flags') {
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Set-Content -Path 'C:\Windows\Temp\simrunner_test.ps1' -Value 'test' -Encoding ascii"
  }
  if ('$sim' -eq 'cmd_to_pwsh_chain') {
    cmd.exe /c "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command ""'test' | Out-File `$env:TEMP\cmd_to_pwsh.txt -Encoding ascii"""
  }

  `$ts2 = (Get-Date).ToUniversalTime().ToString('o') + 'Z'
  Add-Content -Path '$LogPath' -Value ('SIMULATION_RUN id=$sim ts=' + `$ts2 + ' status=done')
} catch {
  `$tsE = (Get-Date).ToUniversalTime().ToString('o') + 'Z'
  Add-Content -Path '$LogPath' -Value ('SIMULATION_RUN id=$sim ts=' + `$tsE + ' status=error msg=' + `$_.Exception.Message)
}
"@

  Start-Process powershell.exe -WindowStyle Hidden -ArgumentList @(
    "-NoProfile","-ExecutionPolicy","Bypass","-Command",$cmd
  ) | Out-Null
}
