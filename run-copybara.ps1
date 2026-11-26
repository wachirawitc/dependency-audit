<#
.SYNOPSIS
    Syncs this repository from GitLab to GitHub with Copybara, using copy.bara.sky.

.DESCRIPTION
    Copybara reads the GitLab origin, not this working tree, so only commits already pushed to
    GitLab develop are synced. The script warns when local develop has unpushed commits.

    If no jar is given or cached, it downloads copybara_deploy.jar from the google/copybara GitHub
    releases into %LOCALAPPDATA%\copybara, checks it against the release's SHA-256 file, and reuses
    it on later runs.

    When the destination repository is empty, the script runs a first sync automatically.

.PARAMETER Init
    Force a first sync (adds --init-history and --force, so the destination branch can be
    created). Not needed for an empty repository, which is detected; use it when the repository
    has other content but no destination branch yet.

.PARAMETER DryRun
    Run the migration without pushing (adds --dry-run).

.PARAMETER JarPath
    Path to an existing copybara_deploy.jar. Skips the download.

.PARAMETER Version
    Copybara release tag to download, for example v20250519. Defaults to the latest release.

.PARAMETER CopybaraArgs
    Extra arguments passed to Copybara as they are, for example --force.

.EXAMPLE
    .\run-copybara.ps1              # sync; an empty destination gets a first sync automatically
    .\run-copybara.ps1 -DryRun
#>
[CmdletBinding()]
param(
    [switch] $Init,
    [switch] $DryRun,
    [string] $JarPath,
    [string] $Version,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $CopybaraArgs = @()
)

$ErrorActionPreference = 'Stop'
$repoRoot = $PSScriptRoot
$config = Join-Path $repoRoot 'copy.bara.sky'

if (-not (Test-Path $config)) {
    throw "copy.bara.sky not found in $repoRoot"
}
if (-not (Get-Command java -ErrorAction SilentlyContinue)) {
    throw 'Java is not on PATH. Install a JDK (11 or later) and try again.'
}

# Locate or download the Copybara jar.
if (-not $JarPath) {
    $cacheDir = Join-Path $env:LOCALAPPDATA 'copybara'
    $tag = $Version
    if (-not $tag) {
        Write-Host 'Looking up the latest Copybara release...'
        $release = Invoke-RestMethod -Uri 'https://api.github.com/repos/google/copybara/releases/latest' `
            -Headers @{ 'User-Agent' = 'run-copybara' }
        $tag = $release.tag_name
    }
    $JarPath = Join-Path $cacheDir "copybara_deploy-$tag.jar"
    if (-not (Test-Path $JarPath)) {
        New-Item -ItemType Directory -Force -Path $cacheDir | Out-Null
        $url = "https://github.com/google/copybara/releases/download/$tag/copybara_deploy.jar"
        Write-Host "Downloading Copybara $tag..."
        $tmp = "$JarPath.download"
        Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing

        # Verify against the release's published checksum before using the jar.
        $sumContent = (Invoke-WebRequest -Uri "$url.sha256" -UseBasicParsing).Content
        if ($sumContent -is [byte[]]) { $sumContent = [System.Text.Encoding]::ASCII.GetString($sumContent) }
        $expected = ($sumContent.Trim() -split '\s+')[0].ToLower()
        $actual = (Get-FileHash -Algorithm SHA256 $tmp).Hash.ToLower()
        if ($expected -ne $actual) {
            Remove-Item -Force $tmp
            throw "Checksum mismatch for copybara_deploy.jar (expected $expected, got $actual)."
        }
        Move-Item -Force $tmp $JarPath
    }
}
elseif (-not (Test-Path $JarPath)) {
    throw "Copybara jar not found: $JarPath"
}

# Copybara syncs what is on GitLab, so warn about local commits that haven't been pushed.
Push-Location $repoRoot
try {
    git fetch --quiet origin develop 2>$null
    if ($LASTEXITCODE -eq 0) {
        $unpushed = git rev-list --count origin/develop..develop 2>$null
        if ($LASTEXITCODE -eq 0 -and [int]$unpushed -gt 0) {
            Write-Warning "$unpushed local commit(s) on develop are not pushed to GitLab and will not be synced."
        }
    }
    else {
        Write-Warning 'Could not fetch origin/develop; skipping the unpushed-commits check.'
    }

    # Copybara needs $HOME (for its ~/copybara work directory), which Windows doesn't set by default.
    if (-not $env:HOME) { $env:HOME = $env:USERPROFILE }

    # Detect an empty destination repository and switch to a first sync automatically.
    $configText = Get-Content -Raw $config
    $destUrl = [regex]::Match($configText, 'DESTINATION_URL\s*=\s*"([^"]+)"').Groups[1].Value
    $destBranch = [regex]::Match($configText, 'git\.destination\([^)]*?push\s*=\s*"([^"]+)"', 'Singleline').Groups[1].Value
    if (-not $Init -and $destUrl -and $destBranch) {
        $refs = @(git ls-remote $destUrl 2>&1)
        if ($LASTEXITCODE -ne 0) {
            throw "Cannot reach $destUrl. Create the repository (it can be empty) and check your GitHub sign-in.`n$($refs -join "`n")"
        }
        $refs = @($refs | Where-Object { $_ -match '\srefs/' })
        if ($refs.Count -eq 0) {
            Write-Host "$destUrl is empty: running a first sync (--init-history --force)."
            $Init = $true
        }
        elseif (-not ($refs | Where-Object { $_ -match "\srefs/heads/$([regex]::Escape($destBranch))$" })) {
            throw "$destUrl has content but no '$destBranch' branch. Run with -Init to create it from the full history."
        }
    }

    $argsList = @('-jar', $JarPath, 'migrate', $config)
    # --force lets Copybara create the branch in a destination that doesn't have it yet.
    if ($Init) { $argsList += '--init-history', '--force' }
    if ($DryRun) { $argsList += '--dry-run' }
    $argsList += $CopybaraArgs

    Write-Host "java $($argsList -join ' ')"
    & java @argsList
    $code = $LASTEXITCODE
}
finally {
    Pop-Location
}

# Copybara exit code 4 means there was nothing new to sync.
if ($code -eq 4) {
    Write-Host 'Nothing to sync: GitHub is already up to date.'
    exit 0
}
exit $code
