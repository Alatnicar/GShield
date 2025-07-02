# GSecurity-RootkitHunter.ps1
# Merged version with persistent background monitoring

function Register-SystemLogonScript {
    param (
        [string]$TaskName = "GSecurityRootkitHunter"
    )

    $scriptSource = $MyInvocation.MyCommand.Path
    if (-not $scriptSource) {
        $scriptSource = $PSCommandPath
        if (-not $scriptSource) {
            Write-Log "Error: Could not determine script path." -EntryType "Error"
            return
        }
    }

    $targetFolder = "C:\Windows\Setup\Scripts\Bin"
    $targetPath = Join-Path $targetFolder (Split-Path $scriptSource -Leaf)

    if (-not (Test-Path $targetFolder)) {
        New-Item -Path $targetFolder -ItemType Directory -Force | Out-Null
        Write-Log "Created folder: $targetFolder"
    }

    try {
        Copy-Item -Path $scriptSource -Destination $targetPath -Force -ErrorAction Stop
        Write-Log "Copied script to: $targetPath"
    } catch {
        Write-Log "Failed to copy script: $_" -EntryType "Error"
        return
    }

    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$targetPath`" -WindowStyle Hidden"
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal
        Write-Log "Scheduled task '$TaskName' created to run at logon"
    } catch {
        Write-Log "Failed to register task: $_" -EntryType "Error"
    }
}

function Write-Log {
    param (
        [string]$Message,
        [string]$EntryType = "Information"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$EntryType] $Message"
    
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists("GSecurity")) {
            New-EventLog -LogName Application -Source "GSecurity"
        }
        Write-EventLog -LogName Application -Source "GSecurity" -EntryType $EntryType -EventId 1000 -Message $Message
    } catch {
        Add-Content -Path "$env:TEMP\GSecurity.log" -Value $logEntry
    }
    
    # Also output to console when running interactively
    if ($Host.Name -match "ConsoleHost") {
        switch ($EntryType) {
            "Error" { Write-Host $logEntry -ForegroundColor Red }
            "Warning" { Write-Host $logEntry -ForegroundColor Yellow }
            default { Write-Host $logEntry -ForegroundColor White }
        }
    }
}

function Disable-Network-Briefly {
    try {
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        foreach ($adapter in $adapters) {
            Disable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction SilentlyContinue
        }
        Start-Sleep -Seconds 3
        foreach ($adapter in $adapters) {
            Enable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction SilentlyContinue
        }
        Write-Log "Network briefly disabled"
    } catch {
        Write-Log "Failed to toggle network: $_" -EntryType "Error"
    }
}

function Add-XSSFirewallRule {
    param ([string]$url)
    try {
        $uri = [System.Uri]::new($url)
        $domain = $uri.Host
        $ruleName = "Block_XSS_$domain"

        if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $ruleName `
                -Direction Outbound `
                -Action Block `
                -RemoteAddress $domain `
                -Protocol TCP `
                -Profile Any `
                -Description "Blocked due to potential XSS in URL"
            Write-Log "Domain blocked via firewall: $domain"
        }
    } catch {
        Write-Log "Could not block: $url" -EntryType "Warning"
    }
}

function Start-RootkitHunter {
    # Whitelist (safe processes)
    $whitelist = @(
        "svchost", "System", "lsass", "wininit", "csrss", "winlogon", 
        "services", "explorer", "dwm", "spoolsv", "taskhostw", "WmiPrvSE",
        "msmpeng", "NisSrv", "ShellExperienceHost", "SearchIndexer", "RuntimeBroker"
    )

    while ($true) {
        try {
            # 1. Check hidden processes (WMI vs tasklist)
            $visible = tasklist /fo csv | ConvertFrom-Csv | Select-Object -ExpandProperty "PID"
            $all = Get-WmiObject Win32_Process | Select-Object -ExpandProperty ProcessId
            $hidden = Compare-Object -ReferenceObject $visible -DifferenceObject $all | 
                     Where-Object { $_.SideIndicator -eq "=>" } | 
                     Select-Object -ExpandProperty InputObject

            # 2. Check network connections
            $connections = Get-NetTCPConnection | Where-Object {
                $_.RemoteAddress -match '^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[01])\.'
            }
            $lanProcIds = $connections.OwningProcess | Sort-Object -Unique

            # Combine both detection methods
            $targetPids = ($hidden + $lanProcIds) | Select-Object -Unique

            foreach ($pid in $targetPids) {
                try {
                    $proc = Get-Process -Id $pid -ErrorAction Stop
                    $procName = $proc.ProcessName
                    $isWhitelisted = ($whitelist -contains $procName)

                    if (-not $isWhitelisted) {
                        $exePath = $proc.Path
                        $shouldKill = $false

                        if ($exePath) {
                            $signature = Get-AuthenticodeSignature -FilePath $exePath
                            if ($signature.Status -ne 'Valid') {
                                $shouldKill = $true
                                $reason = "Unsigned process"
                            }
                        } else {
                            $shouldKill = $true
                            $reason = "No executable path"
                        }

                        if ($shouldKill) {
                            Stop-Process -Id $pid -Force -ErrorAction Stop
                            Write-Log "Terminated suspicious process: $procName (PID: $pid) - $reason"
                        }
                    }
                } catch {
                    Write-Log "Error processing PID $pid`: $_" -EntryType "Warning"
                }
            }

            # 3. XSS monitoring
            $pattern = '(?i)(<script|javascript:|onerror=|onload=|alert\()'
            $procs = Get-WmiObject Win32_Process | Where-Object { $_.CommandLine -match $pattern }
            
            foreach ($proc in $procs) {
                if ($proc.CommandLine -match 'https?://[^\s"]+') {
                    $url = $matches[0]
                    Disable-Network-Briefly
                    Add-XSSFirewallRule -url $url
                    Write-Log "XSS pattern detected in process: $($proc.Name) (PID: $($proc.ProcessId))"
                }
            }

            Start-Sleep -Seconds 30
        } catch {
            Write-Log "Main monitoring error: $_" -EntryType "Error"
            Start-Sleep -Seconds 60
        }
    }
}


Set-ProcessMitigation -System -Enable DisableExtensionPoints  # Blocks process hollowing
Set-NetFirewallProfile -All -DefaultInboundAction Block      # Locks down inbound traffic
New-ItemProperty [...] -Name "RunAsPPL" -Value 1            # Protects LSASS


# Main execution
if ($MyInvocation.MyCommand.CommandType -eq "Script") {
    Register-SystemLogonScript
    
    # Start as background job if not already running
    if (-not (Get-Job -Name "GSecurityRootkitHunter" -ErrorAction SilentlyContinue)) {
        Start-Job -Name "GSecurityRootkitHunter" -ScriptBlock {
            . $using:PSCommandPath
            Start-RootkitHunter
        } | Out-Null
        Write-Log "Started background monitoring job"
    } else {
        Write-Log "Monitoring job already running"
    }

    # Run immediate scan
    Start-RootkitHunter
}