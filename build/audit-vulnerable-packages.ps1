#requires -Version 7
<#
.SYNOPSIS
  Fails when any direct or transitive package has a High or Critical advisory.
.PARAMETER Solution
  Solution or project to audit.
.PARAMETER ReportPath
  Where to write the JSON report produced by `dotnet package list --vulnerable`.
#>
param(
    [string]$Solution = "Pinotechrd.Security.slnx",
    [Parameter(Mandatory = $true)]
    [string]$ReportPath
)

$ErrorActionPreference = "Stop"

New-Item -ItemType Directory -Path (Split-Path -Parent $ReportPath) -Force | Out-Null
dotnet package list --project $Solution --include-transitive --vulnerable --format json --output-version 1 > $ReportPath
if ($LASTEXITCODE -ne 0) { throw "dotnet package list failed with exit code $LASTEXITCODE." }

$report = Get-Content $ReportPath -Raw | ConvertFrom-Json
$blocking = @()

foreach ($project in ($report.projects ?? @())) {
    foreach ($framework in ($project.frameworks ?? @())) {
        $packages = @()
        if ($framework.topLevelPackages) { $packages += $framework.topLevelPackages }
        if ($framework.transitivePackages) { $packages += $framework.transitivePackages }

        foreach ($pkg in $packages) {
            foreach ($v in ($pkg.vulnerabilities ?? @())) {
                $severity = (($v.severity ?? "") | Out-String).Trim().ToLowerInvariant()
                if ($severity -in @("high", "critical")) {
                    $blocking += [PSCustomObject]@{
                        project         = $project.path
                        framework       = $framework.framework
                        package         = $pkg.id
                        resolvedVersion = $pkg.resolvedVersion
                        severity        = $severity
                        advisory        = $v.advisoryurl
                    }
                }
            }
        }
    }
}

if ($blocking.Count -gt 0) {
    Write-Host "Blocking advisories found:"
    $blocking | Format-Table -AutoSize | Out-String | Write-Host
    throw "High/Critical vulnerable packages detected."
}

Write-Host "No High/Critical vulnerable packages detected."
