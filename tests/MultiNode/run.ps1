# Runs the multi-node validation end to end, for one or both schema modes:
#   containers -> provisioning (owner role) -> two nodes (separate processes, Production) -> tests -> teardown.
# Synthetic data in disposable local containers only.
param(
    [ValidateSet('SearchPath', 'SchemaPerTenantInModel', 'Both')]
    [string]$Mode = 'Both',
    [switch]$KeepRunning,
    [string]$LogDirectory = (Join-Path $PSScriptRoot 'logs')
)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$logs = $LogDirectory
New-Item -ItemType Directory -Force $logs | Out-Null

dotnet build (Join-Path $root 'MultiNodeHost') -c Release -nologo -v q | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Host build failed.' }
dotnet build (Join-Path $root 'MultiNodeTests') -c Release -nologo -v q | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Test build failed.' }

$hostDll = [IO.Path]::Combine($root, 'MultiNodeHost', 'bin', 'Release', 'net10.0', 'MultiNodeHost.dll')
$modes = if ($Mode -eq 'Both') { @('SearchPath', 'SchemaPerTenantInModel') } else { @($Mode) }
$results = @()

foreach ($m in $modes) {
    Write-Host "=== $m ==="
    Push-Location $root
    try {
        docker compose down -v --remove-orphans 2>&1 | Out-Null
        docker compose up -d --wait 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Containers did not start.' }
    } finally { Pop-Location }

    # One random signing secret and one fresh key folder per run, shared by both nodes as a secret store would.
    $secret = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(48))
    $keys = Join-Path ([IO.Path]::GetTempPath()) ("pinotechrd-multinode-keys-" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory $keys | Out-Null

    $env:SCHEMA_MODE = $m
    $env:JWT_SECRET = $secret
    $env:KEYS_DIR = $keys
    dotnet $hostDll provision 2>&1 | Tee-Object -FilePath (Join-Path $logs "provision-$m.log") | Select-Object -Last 1
    if ($LASTEXITCODE -ne 0) { throw 'Provisioning failed.' }

    $nodes = @()
    foreach ($n in @(@{ Name = 'node1'; Port = 5101 }, @{ Name = 'node2'; Port = 5102 })) {
        $env:NODE_NAME = $n.Name
        $env:URLS = "http://localhost:$($n.Port)"
        $nodes += Start-Process dotnet -ArgumentList "`"$hostDll`"" -PassThru -NoNewWindow `
            -RedirectStandardOutput (Join-Path $logs "$($n.Name)-$m.out.log") -RedirectStandardError (Join-Path $logs "$($n.Name)-$m.err.log")
    }

    try {
        foreach ($port in 5101, 5102) {
            $deadline = (Get-Date).AddSeconds(60)
            while ($true) {
                try { Invoke-RestMethod "http://localhost:$port/health" | Out-Null; break }
                catch { if ((Get-Date) -gt $deadline) { throw "Node on $port did not start; see logs." }; Start-Sleep -Milliseconds 500 }
            }
        }

        $env:NODE1 = 'http://localhost:5101'
        $env:NODE2 = 'http://localhost:5102'
        $env:EXPECTED_MODE = $m
        dotnet test (Join-Path $root 'MultiNodeTests') -c Release --no-build --logger "trx;LogFileName=multinode-$m.trx" --results-directory $logs 2>&1 |
            Tee-Object -FilePath (Join-Path $logs "tests-$m.log") | Select-String -Pattern '^\s+Failed |Passed!|Failed!'
        $results += [pscustomobject]@{ Mode = $m; ExitCode = $LASTEXITCODE }
    }
    finally {
        if (-not $KeepRunning) {
            $nodes | ForEach-Object { if (-not $_.HasExited) { Stop-Process -Id $_.Id -Force } }
            Remove-Item -Recurse -Force $keys -ErrorAction SilentlyContinue
        }
    }
}

if (-not $KeepRunning) {
    Push-Location $root
    try { docker compose down -v --remove-orphans 2>&1 | Out-Null } finally { Pop-Location }
}

$results | Format-Table -AutoSize
if ($results | Where-Object ExitCode -ne 0) { exit 1 }
