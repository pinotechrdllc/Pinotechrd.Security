param([switch]$Full, [string]$Filter, [string]$Root)
# Narrow gate (default, used by the Stop hook): Release build with warnings as errors, then every test outside
# the Postgres folder. -Full mirrors .github/workflows/ci.yml (package audit, all tests, coverage floor); keep the
# two in step with that file, which is the source of truth. -Filter overrides the narrow test filter.
# -Root runs the gate against another checkout of this repo, such as a git worktree.
$ErrorActionPreference = 'Stop'
if (-not $Root) { $Root = Join-Path $PSScriptRoot '..' }
Set-Location $Root
$sln = 'Pinotechrd.Security.slnx'
$tests = 'tests/Pinotechrd.Security.Tests/Pinotechrd.Security.Tests.csproj'

dotnet build $sln -c Release -warnaserror --nologo -v q
if ($LASTEXITCODE) { exit 1 }

if ($Full) {
    # The audit script requires PowerShell 7; the global Stop hook runs this file under Windows PowerShell 5.1.
    pwsh -NoProfile -File ./build/audit-vulnerable-packages.ps1 -ReportPath (Join-Path $env:TEMP 'pinotechrd-nuget-audit.json')
    if ($LASTEXITCODE) { exit 1 }
    dotnet test $tests -c Release --no-build --nologo --verbosity minimal `
        /p:CollectCoverage=true /p:CoverletOutputFormat=cobertura `
        '/p:Include=[Pinotechrd.Security]Pinotechrd.Security.*' `
        /p:Threshold=40 /p:ThresholdType=line /p:ThresholdStat=total
    exit $LASTEXITCODE
}

if (-not $Filter) { $Filter = 'FullyQualifiedName!~Pinotechrd.Security.Tests.Postgres' }
dotnet test $tests -c Release --no-build --nologo --verbosity minimal --filter $Filter
exit $LASTEXITCODE
