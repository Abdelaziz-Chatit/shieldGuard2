# Requires running as Administrator
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

$chromePath = "C:\Program Files\Google\Chrome\Application\chrome.exe"
if (-not (Test-Path $chromePath)) {
    Write-Error "Chrome executable not found at $chromePath. Update the path and rerun."
    exit 1
}

function CreateRuleIfMissing {
    param(
        [string]$Name,
        [string]$Direction,
        [string]$Action,
        [string]$Program,
        [string]$RemoteAddress = "Any",
        [string]$Protocol = "TCP",
        [string]$RemotePort = "Any"
    )
    if (-not (Get-NetFirewallRule -DisplayName $Name -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $Name -Direction $Direction -Program $Program -RemoteAddress $RemoteAddress -Protocol $Protocol -RemotePort $RemotePort -Action $Action
        Write-Host "Created rule: $Name"
    }
    else {
        Write-Host "Rule already exists: $Name"
    }
}

CreateRuleIfMissing -Name "ShieldGuard Allow Chrome Localhost" -Direction Outbound -Action Allow -Program $chromePath -RemoteAddress 127.0.0.1 -Protocol TCP -RemotePort Any
CreateRuleIfMissing -Name "ShieldGuard Block Chrome HTTP/S" -Direction Outbound -Action Block -Program $chromePath -Protocol TCP -RemotePort 80,443
CreateRuleIfMissing -Name "ShieldGuard Block Chrome QUIC" -Direction Outbound -Action Block -Program $chromePath -Protocol UDP -RemotePort 443

Write-Host "Firewall setup complete. Verify with: netsh advfirewall firewall show rule name=""ShieldGuard*"""
