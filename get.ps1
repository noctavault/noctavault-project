#Requires -Version 5.1
<#
Installe Noctavault sur Windows : dependances (WebView2, MSVC Build
Tools via winget) + Rust (si absent), compile nv-node (CLI) et nv-app
(GUI), installe les binaires dans %LOCALAPPDATA%\Noctavault\bin.

Usage :
    irm https://raw.githubusercontent.com/noctavault/noctavault-project/main/get.ps1 | iex

ou, depuis un clone existant, dans un PowerShell ouvert a la racine du
depot :
    .\get.ps1

Si l'execution de scripts est bloquee ("cannot be loaded because
running scripts is disabled"), lance d'abord :
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
#>

$ErrorActionPreference = "Stop"

$RepoUrl = if ($env:NOCTAVAULT_REPO_URL) { $env:NOCTAVAULT_REPO_URL } else { "https://github.com/noctavault/noctavault-project.git" }
$InstallDir = if ($env:NOCTAVAULT_INSTALL_DIR) { $env:NOCTAVAULT_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "Noctavault\bin" }

function Log($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Warn($msg) { Write-Host "!! $msg" -ForegroundColor Yellow }
function Die($msg) { Write-Host "erreur: $msg" -ForegroundColor Red; exit 1 }

function Test-Command($name) {
    return [bool](Get-Command $name -ErrorAction SilentlyContinue)
}

function Install-SystemDeps {
    if (-not (Test-Command "winget")) {
        Warn "winget introuvable (Windows 10 ancien ?) : installe manuellement WebView2"
        Warn "  (https://developer.microsoft.com/microsoft-edge/webview2/) et les"
        Warn "  Visual C++ Build Tools (https://visualstudio.microsoft.com/visual-cpp-build-tools/)"
        Warn "  avant de relancer ce script."
        return
    }

    Log "verification WebView2 (moteur GUI Tauri)"
    winget install --id Microsoft.EdgeWebView2Runtime --silent --accept-package-agreements --accept-source-agreements 2>$null | Out-Null

    Log "verification des Visual C++ Build Tools (compilation Rust)"
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    $hasVc = $false
    if (Test-Path $vswhere) {
        $found = & $vswhere -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if ($found) { $hasVc = $true }
    }
    if ($hasVc) {
        Log "Build Tools deja presents"
    } else {
        Log "installation des Visual C++ Build Tools (peut prendre plusieurs minutes)"
        winget install --id Microsoft.VisualStudio.2022.BuildTools --silent --accept-package-agreements --accept-source-agreements `
            --override "--quiet --wait --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
    }
}

function Install-Rust {
    if (Test-Command "cargo") {
        Log "Rust deja present : $(cargo --version)"
        return
    }
    Log "installation de Rust via rustup"
    $rustupExe = Join-Path $env:TEMP "rustup-init.exe"
    Invoke-WebRequest -Uri "https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe" -OutFile $rustupExe
    & $rustupExe -y --profile default | Out-Null
    Remove-Item $rustupExe -ErrorAction SilentlyContinue
    $cargoBin = Join-Path $env:USERPROFILE ".cargo\bin"
    $env:Path = "$cargoBin;$env:Path"
    if (-not (Test-Command "cargo")) {
        Die "Rust installe mais 'cargo' introuvable : ouvre un nouveau terminal et relance ce script."
    }
}

function Get-Source {
    if ((Test-Path "Cargo.toml") -and (Select-String -Path "Cargo.toml" -Pattern "nv-node" -Quiet)) {
        Log "depot deja present dans le repertoire courant"
        return (Get-Location).Path
    }
    if (Test-Path "noctavault\Cargo.toml") {
        return (Join-Path (Get-Location).Path "noctavault")
    }
    if (-not (Test-Command "git")) {
        Die "git est requis pour cloner le depot (installe-le, ou telecharge le zip depuis GitHub)"
    }
    Log "clonage du depot ($RepoUrl)"
    git clone --depth 1 $RepoUrl noctavault
    return (Join-Path (Get-Location).Path "noctavault")
}

function Build-AndInstall($srcDir) {
    Log "compilation (release) - peut prendre plusieurs minutes"
    Push-Location $srcDir
    try {
        cargo build --release -p nv-node -p nv-app
        if ($LASTEXITCODE -ne 0) { Die "echec de la compilation" }
    } finally {
        Pop-Location
    }

    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Copy-Item (Join-Path $srcDir "target\release\nv-node.exe") (Join-Path $InstallDir "nv-node.exe") -Force
    Copy-Item (Join-Path $srcDir "target\release\nv-app.exe") (Join-Path $InstallDir "nv-app.exe") -Force
    Log "binaires installes dans $InstallDir"

    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($userPath -notlike "*$InstallDir*") {
        [Environment]::SetEnvironmentVariable("Path", "$userPath;$InstallDir", "User")
        Warn "$InstallDir ajoute a ton PATH utilisateur - ouvre un nouveau terminal pour que ca prenne effet"
    }
}

function Main {
    Install-SystemDeps
    Install-Rust
    $src = Get-Source
    Build-AndInstall $src

    Log "installation terminee"
    Write-Host ""
    Write-Host "  nv-node --home `$env:USERPROFILE\.noctavault init     # creer son identite"
    Write-Host "  nv-node --home `$env:USERPROFILE\.noctavault id -o moi.nvid"
    Write-Host "  nv-app                                                # lancer la GUI"
}

Main
