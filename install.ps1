# SentinelGate installer for Windows
# Usage: irm https://raw.githubusercontent.com/Sentinel-Gate/Sentinelgate/main/install.ps1 | iex
#
# Environment variables:
#   VERSION      - specific version to install (e.g., v1.0.0-beta.2). Default: latest
#   INSTALL_DIR  - installation directory. Default: %LOCALAPPDATA%\SentinelGate

# Wrap everything in a script block to avoid leaking variables into caller's session via iex
& {

$ErrorActionPreference = "Stop"

# Ensure TLS 1.2 (required by GitHub; older PS 5.1 defaults to TLS 1.0/1.1)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Suppress progress bar (PS 5.1 progress rendering is pathologically slow on large downloads)
$ProgressPreference = 'SilentlyContinue'

$Repo = "Sentinel-Gate/Sentinelgate"
$BinaryName = "sentinel-gate"

# ── Logging ──────────────────────────────────────────────────────────────────

function Write-Info { param([string]$Message) Write-Host "=> " -ForegroundColor Blue -NoNewline; Write-Host $Message }
function Write-Ok { param([string]$Message) Write-Host "=> " -ForegroundColor Green -NoNewline; Write-Host $Message }
function Write-Warn { param([string]$Message) Write-Host "WARNING: " -ForegroundColor Yellow -NoNewline; Write-Host $Message }
function Write-Err { param([string]$Message) Write-Host "ERROR: " -ForegroundColor Red -NoNewline; Write-Host $Message; throw "Installation failed: $Message" }

# ── Architecture detection ───────────────────────────────────────────────────

function Get-Arch {
    $arch = $env:PROCESSOR_ARCHITECTURE
    switch ($arch) {
        "AMD64" { return "amd64" }
        "ARM64" { return "arm64" }
        default {
            # On ARM64 running x86 emulation, check PROCESSOR_ARCHITEW6432
            $archW6432 = $env:PROCESSOR_ARCHITEW6432
            if ($archW6432 -eq "ARM64") { return "arm64" }
            if ($archW6432 -eq "AMD64") { return "amd64" }
            Write-Err "Unsupported architecture: $arch. Only amd64 and arm64 are supported."
        }
    }
}

# ── Version resolution ───────────────────────────────────────────────────────

function Get-Version {
    if ($env:VERSION) {
        $v = $env:VERSION
        if ($v -notmatch '^v') { $v = "v$v" }
        Write-Info "Using specified version: $v"
        return $v
    }

    Write-Info "Fetching latest release version..."

    try {
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest"
        $version = $release.tag_name
    } catch {
        Write-Info "No stable release found, checking pre-releases..."
        try {
            $releases = @(Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases")
            $version = $releases[0].tag_name
        } catch {
            Write-Err "Failed to fetch releases from GitHub API: $_"
        }
    }

    if (-not $version) {
        Write-Err "Could not determine latest version from GitHub API."
    }

    Write-Info "Latest version: $version"
    return $version
}

# ── Download and verify ──────────────────────────────────────────────────────

function Install-SentinelGate {
    Write-Host ""
    Write-Host "SentinelGate Installer" -ForegroundColor White -BackgroundColor DarkCyan
    Write-Host ""

    $arch = Get-Arch
    $version = Get-Version

    $archiveName = "${BinaryName}_windows_${arch}.zip"
    $archiveUrl = "https://github.com/$Repo/releases/download/$version/$archiveName"
    $checksumsUrl = "https://github.com/$Repo/releases/download/$version/checksums.txt"

    $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) "sentinelgate-install-$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

    try {
        # Download archive
        Write-Info "Downloading $archiveName..."
        $archivePath = Join-Path $tmpDir $archiveName
        try {
            Invoke-WebRequest -Uri $archiveUrl -OutFile $archivePath -UseBasicParsing
        } catch {
            Write-Err "Failed to download archive from ${archiveUrl}: $_"
        }

        # Download checksums
        Write-Info "Downloading checksums..."
        $checksumsPath = Join-Path $tmpDir "checksums.txt"
        try {
            Invoke-WebRequest -Uri $checksumsUrl -OutFile $checksumsPath -UseBasicParsing
        } catch {
            Write-Err "Failed to download checksums from ${checksumsUrl}: $_"
        }

        # Verify checksum
        Write-Info "Verifying SHA-256 checksum..."
        $escapedName = [regex]::Escape($archiveName)
        $checksumLine = Get-Content $checksumsPath | Where-Object { $_ -match "\s+${escapedName}$" } | Select-Object -First 1
        if (-not $checksumLine) {
            Write-Err "Could not find checksum for $archiveName in checksums.txt"
        }
        $expected = ($checksumLine -split '\s+')[0]
        $actual = (Get-FileHash -Path $archivePath -Algorithm SHA256).Hash.ToLower()

        if ($expected -ne $actual) {
            Write-Err "Checksum mismatch for $archiveName`n  Expected: $expected`n  Actual:   $actual"
        }
        Write-Ok "Checksum verified."

        # Extract
        Write-Info "Extracting $BinaryName..."
        Expand-Archive -Path $archivePath -DestinationPath $tmpDir -Force

        $binaryPath = Join-Path $tmpDir "$BinaryName.exe"
        if (-not (Test-Path $binaryPath)) {
            Write-Err "Binary '$BinaryName.exe' not found in archive."
        }

        # Determine install directory
        if ($env:INSTALL_DIR) {
            $installDir = $env:INSTALL_DIR
        } else {
            $installDir = Join-Path $env:LOCALAPPDATA "SentinelGate"
        }

        if (-not (Test-Path $installDir)) {
            New-Item -ItemType Directory -Path $installDir -Force | Out-Null
        }

        $destPath = Join-Path $installDir "$BinaryName.exe"

        # Check if binary is locked (already running)
        if (Test-Path $destPath) {
            try {
                [IO.File]::Open($destPath, 'Open', 'ReadWrite', 'Read').Close()
            } catch {
                Write-Err "$BinaryName.exe is currently running. Please stop it first (sentinel-gate stop) and re-run the installer."
            }
        }

        # Remove "downloaded from internet" mark to avoid SmartScreen popup
        Unblock-File -Path $binaryPath
        Copy-Item -Path $binaryPath -Destination $destPath -Force

        # Add to PATH if not already there
        $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
        $pathEntries = ($userPath -split ';') | Where-Object { $_ -ne '' }
        if ($installDir -notin $pathEntries) {
            Write-Info "Adding $installDir to user PATH..."
            $newPath = if ([string]::IsNullOrEmpty($userPath)) { $installDir } else { "$userPath;$installDir" }
            [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
            $env:Path = "$env:Path;$installDir"
            Write-Warn "Restart your terminal for PATH changes to take effect."
        }

        Write-Host ""
        Write-Ok "SentinelGate $version installed successfully!"
        Write-Info "Binary: $destPath"
        Write-Info "Run 'sentinel-gate start' to get started."
        Write-Host ""

    } finally {
        # Cleanup
        if (Test-Path $tmpDir) {
            Remove-Item -Path $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

try {
    Install-SentinelGate
} catch {
    if ($_.Exception.Message -notlike "Installation failed:*") {
        Write-Host "ERROR: " -ForegroundColor Red -NoNewline
        Write-Host "Unexpected error: $($_.Exception.Message)"
    }
}

} # end of script block scope
