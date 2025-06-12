# PowerShell script to secure Windows Pro/Enterprise/Education from remote access
# Requires Administrator privileges
# Run in an elevated PowerShell session

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator. Exiting..." -ForegroundColor Red
    exit
}

Write-Host "Starting Windows Remote Access Security Hardening..." -ForegroundColor Green

# 1. Disable Remote Desktop (RDP)
Write-Host "Disabling Remote Desktop..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1
# Disable Remote Assistance
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0
Write-Host "Remote Desktop and Remote Assistance disabled."

# 2. Block RDP port (3389) and other common remote access ports in Windows Firewall
Write-Host "Configuring firewall to block common remote access ports..."
# Block RDP (3389)
New-NetFirewallRule -DisplayName "Block RDP Inbound" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Block -Enabled True
# Block common VNC ports (5900-5902)
New-NetFirewallRule -DisplayName "Block VNC Inbound" -Direction Inbound -Protocol TCP -LocalPort 5900-5902 -Action Block -Enabled True
# Block TeamViewer port (5938)
New-NetFirewallRule -DisplayName "Block TeamViewer Inbound" -Direction Inbound -Protocol TCP -LocalPort 5938 -Action Block -Enabled True
# Block AnyDesk port (7070)
New-NetFirewallRule -DisplayName "Block AnyDesk Inbound" -Direction Inbound -Protocol TCP -LocalPort 7070 -Action Block -Enabled True
Write-Host "Firewall rules added to block RDP, VNC, TeamViewer, and AnyDesk ports."

# 3. Disable Remote Desktop Services via Group Policy (if available)
Write-Host "Configuring Group Policy to disable Remote Desktop Services..."
$gpPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
if (-not (Test-Path $gpPath)) {
    New-Item -Path $gpPath -Force | Out-Null
}
Set-ItemProperty -Path $gpPath -Name "fDenyTSConnections" -Value 1
Write-Host "Group Policy updated to disable Remote Desktop Services."

# 4. Disable default Administrator account
Write-Host "Disabling default Administrator account..."
$adminAccount = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
if ($adminAccount) {
    Disable-LocalUser -Name "Administrator"
    Write-Host "Default Administrator account disabled."
} else {
    Write-Host "Default Administrator account not found or already disabled."
}

# 5. Restrict unauthorized software installation via Group Policy
Write-Host "Restricting unauthorized software (e.g., TeamViewer, AnyDesk)..."
$restrictPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if (-not (Test-Path $restrictPath)) {
    New-Item -Path $restrictPath -Force | Out-Null
}
# Example: Block TeamViewer and AnyDesk executables
$blockedApps = "TeamViewer.exe,AnyDesk.exe"
Set-ItemProperty -Path $restrictPath -Name "DisallowRun" -Value 1
New-Item -Path "$restrictPath\DisallowRun" -Force | Out-Null
$blockedApps.Split(",") | ForEach-Object { Set-ItemProperty -Path "$restrictPath\DisallowRun" -Name $_ -Value $_ }
Write-Host "Group Policy updated to block specified remote access software."

# 6. Disable UPnP in Windows (prevents automatic port forwarding)
Write-Host "Disabling UPnP service..."
Set-Service -Name "SSDPSRV" -StartupType Disabled
Stop-Service -Name "SSDPSRV" -Force -ErrorAction SilentlyContinue
Write-Host "UPnP service disabled."

# 7. Enable Windows Defender real-time protection
Write-Host "Ensuring Windows Defender real-time protection is enabled..."
Set-MpPreference -DisableRealtimeMonitoring $false
Write-Host "Windows Defender real-time protection enabled."

# 8. Verify RDP is not listening
Write-Host "Verifying RDP port (3389) is not listening..."
$rdpPort = netstat -an | Select-String "3389"
if ($rdpPort) {
    Write-Host "WARNING: Port 3389 is still listening. Please check firewall and service settings manually." -ForegroundColor Yellow
} else {
    Write-Host "RDP port 3389 is not listening."
}

# 9. Log completion
Write-Host "Security hardening complete!" -ForegroundColor Green
Write-Host "Recommended manual steps:"
Write-Host "- Check Event Viewer for unauthorized access attempts."
Write-Host "- Ensure Windows is up to date via Settings > Windows Update."
Write-Host "- Consider using a VPN for secure remote access if needed."
Write-Host "- Verify firewall rules and test remote access to ensure it is blocked."