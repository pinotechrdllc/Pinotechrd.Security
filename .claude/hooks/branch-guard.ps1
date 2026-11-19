# PreToolUse (Bash): refuse to create or rename a branch unless its name is <type>/<issue>-<slug> and the issue is
# open on GitHub. Exit 2 blocks the command and returns the message to Claude.
$ErrorActionPreference = 'SilentlyContinue'
$hook = [Console]::In.ReadToEnd() | ConvertFrom-Json
$command = [string]$hook.tool_input.command
if (-not $command -or $command -notmatch '\bgit\b') { exit 0 }

$names = New-Object System.Collections.Generic.List[string]
$patterns = @(
    '\bgit\s+(?:-C\s+\S+\s+)?checkout\s+(?:\S+\s+)*?-[bB]\s+([^\s;&|]+)',
    '\bgit\s+(?:-C\s+\S+\s+)?switch\s+(?:\S+\s+)*?(?:-[cC]|--create|--force-create)\s+([^\s;&|]+)',
    '\bgit\s+(?:-C\s+\S+\s+)?worktree\s+add\s+(?:\S+\s+)*?-[bB]\s+([^\s;&|]+)',
    '\bgit\s+(?:-C\s+\S+\s+)?branch\s+-[mMcC]\s+(?:[^\s;&|]+\s+)?([^\s;&|]+)',
    '\bgit\s+(?:-C\s+\S+\s+)?branch\s+(?!-)([^\s;&|]+)'
)
foreach ($pattern in $patterns) {
    foreach ($match in [regex]::Matches($command, $pattern)) { $names.Add($match.Groups[1].Value.Trim('"', "'")) }
}
if ($names.Count -eq 0) { exit 0 }

if ($env:CLAUDE_PROJECT_DIR) { Set-Location $env:CLAUDE_PROJECT_DIR }
foreach ($name in $names) {
    if ($name -notmatch '^(feat|fix|chore|docs|refactor|test|perf|ci|build)/(\d+)-[a-z0-9][a-z0-9-]*$') {
        [Console]::Error.WriteLine("Branch '$name' refused: name it <type>/<issue>-<slug>, e.g. fix/14-revoke-on-delete, after creating the GitHub issue.")
        exit 2
    }
    $issue = $Matches[2]
    $state = gh issue view $issue --json state -q .state 2>$null
    if ($state -ne 'OPEN') {
        [Console]::Error.WriteLine("Branch '$name' refused: issue #$issue is not an open issue of this repository (gh returned '$state').")
        exit 2
    }
}
exit 0
