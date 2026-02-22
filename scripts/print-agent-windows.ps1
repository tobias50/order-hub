# Order Hub print agent (Windows)
# Polls Order Hub for next ready job, downloads merged PDF, prints it, reports result.
#
# Requirements:
# - PowerShell 5+
# - SumatraPDF installed (default path below)
# - Printer driver installed on this machine
#
# Run from Task Scheduler every minute:
# powershell.exe -ExecutionPolicy Bypass -File "C:\path\to\print-agent-windows.ps1"

param(
    [string]$HubBaseUrl = "https://ordrehub.nordicprofil.no",
    [string]$PrintToken = "SET_PRINT_TOKEN_HERE",
    [string]$PrinterName = "SET_PRINTER_NAME_HERE",
    [string]$AgentName = "lager-pc-1",
    [string]$SumatraPath = "C:\Program Files\SumatraPDF\SumatraPDF.exe"
)

$ErrorActionPreference = "Stop"

if ($PrintToken -eq "" -or $PrintToken -eq "SET_PRINT_TOKEN_HERE") {
    throw "Set -PrintToken before running."
}
if ($PrinterName -eq "" -or $PrinterName -eq "SET_PRINTER_NAME_HERE") {
    throw "Set -PrinterName before running."
}
if (-not (Test-Path $SumatraPath)) {
    throw "SumatraPDF not found: $SumatraPath"
}

$headers = @{
    "X-NP-Print-Token" = $PrintToken
    "Content-Type"     = "application/json"
}

$claimUrl = "$HubBaseUrl/wp-json/np-order-hub/v1/print-agent/claim"
$finishUrl = "$HubBaseUrl/wp-json/np-order-hub/v1/print-agent/finish"

function Finish-Job([string]$jobKey, [string]$claimId, [bool]$success, [string]$errorMessage) {
    $payload = @{
        job_key  = $jobKey
        claim_id = $claimId
        success  = $success
        error    = $errorMessage
    } | ConvertTo-Json -Depth 4

    Invoke-RestMethod -Method Post -Uri $finishUrl -Headers $headers -Body $payload | Out-Null
}

try {
    $claimBody = @{ agent = $AgentName } | ConvertTo-Json -Depth 3
    $claim = Invoke-RestMethod -Method Post -Uri $claimUrl -Headers $headers -Body $claimBody

    if (-not $claim -or $claim.status -ne "claimed" -or -not $claim.job) {
        exit 0
    }

    $job = $claim.job
    $jobKey = [string]$job.job_key
    $claimId = [string]$job.claim_id
    $documentUrl = [string]$job.document_url

    if ($jobKey -eq "" -or $claimId -eq "" -or $documentUrl -eq "") {
        Finish-Job -jobKey $jobKey -claimId $claimId -success $false -errorMessage "Missing job fields from claim response."
        exit 1
    }

    $tempDir = Join-Path $env:TEMP "np-order-hub-print-agent"
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    $fileName = if ($job.document_filename) { [string]$job.document_filename } else { "order-$($job.order_id).pdf" }
    $localPath = Join-Path $tempDir $fileName

    Invoke-WebRequest -Uri $documentUrl -OutFile $localPath

    if (-not (Test-Path $localPath)) {
        Finish-Job -jobKey $jobKey -claimId $claimId -success $false -errorMessage "Downloaded file missing."
        exit 1
    }

    $printArgs = @(
        "-print-to", $PrinterName,
        "-silent",
        "-exit-when-done",
        $localPath
    )

    $proc = Start-Process -FilePath $SumatraPath -ArgumentList $printArgs -PassThru -Wait
    if ($proc.ExitCode -ne 0) {
        Finish-Job -jobKey $jobKey -claimId $claimId -success $false -errorMessage "Sumatra exit code $($proc.ExitCode)."
        exit 1
    }

    Finish-Job -jobKey $jobKey -claimId $claimId -success $true -errorMessage ""
    Remove-Item -Path $localPath -Force -ErrorAction SilentlyContinue
    exit 0
}
catch {
    $message = $_.Exception.Message
    if ($message -eq $null -or $message -eq "") {
        $message = "Unknown print agent error."
    }
    try {
        if ($jobKey -and $claimId) {
            Finish-Job -jobKey $jobKey -claimId $claimId -success $false -errorMessage $message
        }
    }
    catch {
    }
    throw
}
