<#
.SYNOPSIS
    NEON//PING launcher (PowerShell). Starts neonping.py from the same folder.

.DESCRIPTION
    Without parameters the GUI starts without a console window (pythonw, falling
    back to pyw / python). With -Console it runs through python.exe in this window,
    so any traceback stays visible.

.PARAMETER Console
    Run with a visible console (debugging).

.EXAMPLE
    .\start.ps1
    .\start.ps1 -Console
#>
[CmdletBinding()]
param(
    [switch]$Console
)

$scriptPath = Join-Path $PSScriptRoot 'neonping.py'

if (-not (Test-Path -LiteralPath $scriptPath)) {
    Write-Host "[NEON//PING] Cannot find $scriptPath" -ForegroundColor Red
    exit 1
}

function Find-Launcher {
    param([string[]]$Names)
    foreach ($name in $Names) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
    }
    return $null
}

function Get-LaunchArgs {
    param([string]$Exe, [string]$Script, [switch]$Quote)
    # py.exe / pyw.exe expect the Python version as the first argument.
    # Start-Process joins arguments with spaces and no quoting, so the path is quoted
    # explicitly there (-Quote); the & operator quotes by itself and gets the bare path.
    $path = if ($Quote) { "`"$Script`"" } else { $Script }
    $leaf = Split-Path -Path $Exe -Leaf
    if ($leaf -ieq 'py.exe' -or $leaf -ieq 'pyw.exe') {
        return @('-3', $path)
    }
    return @($path)
}

if ($Console) {
    $exe = Find-Launcher @('python', 'py')
    if (-not $exe) {
        Write-Host '[NEON//PING] Python was not found in PATH.' -ForegroundColor Red
        exit 1
    }
    Write-Host "[NEON//PING] $exe -> $scriptPath" -ForegroundColor Cyan
    $launchArgs = Get-LaunchArgs -Exe $exe -Script $scriptPath
    & $exe @launchArgs
    exit $LASTEXITCODE
}

$exe = Find-Launcher @('pythonw', 'pyw', 'python')
if (-not $exe) {
    Write-Host '[NEON//PING] Python was not found in PATH.' -ForegroundColor Red
    Write-Host '             Install Python 3 (python.org) or add python.exe to PATH.'
    exit 1
}

$launchArgs = Get-LaunchArgs -Exe $exe -Script $scriptPath -Quote
Start-Process -FilePath $exe -ArgumentList $launchArgs -WorkingDirectory $PSScriptRoot
