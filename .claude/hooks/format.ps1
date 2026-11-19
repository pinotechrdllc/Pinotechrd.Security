# PostToolUse (Edit|Write): fix whitespace of the edited C# file with the repo's .editorconfig (CRLF, indentation).
# Whitespace only: it needs no build, so it stays fast. Never blocks the edit.
$ErrorActionPreference = 'SilentlyContinue'
$hook = [Console]::In.ReadToEnd() | ConvertFrom-Json
$path = $hook.tool_input.file_path
if (-not $path -or -not $path.EndsWith('.cs') -or -not (Test-Path $path)) { exit 0 }

$root = if ($env:CLAUDE_PROJECT_DIR) { $env:CLAUDE_PROJECT_DIR } else { (Get-Location).Path }
$full = (Resolve-Path $path).Path
if (-not $full.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) { exit 0 }
$relative = $full.Substring($root.Length).TrimStart('\', '/')

dotnet format whitespace $root --folder --include $relative | Out-Null
exit 0
