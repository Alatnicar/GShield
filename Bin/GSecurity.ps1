#Requires -RunAsAdministrator

<#
    GSecurity.ps1
    Author: Gorstak
    Description: Windows security script with YARA/Sigma/Snort rule parsing, security rule application, and process monitoring as a background job
#>

# Define parameters
param (
    [switch]$Start,
    [string]$SnortOinkcode = "6cc50dfad45e71e9d8af44485f59af2144ad9a3c", # Configurable Oinkcode
    [switch]$DebugMode,
    [switch]$NoMonitor, # Monitoring is enabled by default unless this is specified
    [string]$ConfigPath = "$env:USERPROFILE\GSecurity_config.json"
)

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

# Add proper exit code handling
function Exit-Script {
    param (
        [int]$ExitCode = 0,
        [string]$Message = ""
    )
    if ($Message) {
        if ($ExitCode -ne 0) {
            Write-Log $Message -EntryType "Error"
        } else {
            Write-Log $Message -EntryType "Information"
        }
    }
    exit $ExitCode
}

# Initialize Event Log source
function Initialize-EventLog {
    if (-not [System.Diagnostics.EventLog]::SourceExists("SecureWindows")) {
        New-EventLog -LogName "Application" -Source "SecureWindows"
        Write-Log "Created Event Log source: SecureWindows"
    }
}

# Log function with truncation and file logging
function Write-Log {
    param (
        [string]$Message,
        [string]$EntryType = "Information"
    )
    $maxEventLogLength = 32766
    $logDir = "$env:TEMP\security_rules\logs"
    $logFile = "$logDir\SecureWindows_$(Get-Date -Format 'yyyyMMdd').log"
    
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    
    $truncatedMessage = if ($Message.Length -gt $maxEventLogLength) {
        $Message.Substring(0, $maxEventLogLength - 100) + "... [Truncated, see log file]"
    } else {
        $Message
    }
    
    Write-Host "[$EntryType] $truncatedMessage" -ForegroundColor $(switch ($EntryType) { "Error" { "Red" } "Warning" { "Yellow" } default { "White" } })
    
    $logEntry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$EntryType] $Message"
    $logEntry | Out-File -FilePath $logFile -Append -Encoding UTF8
    
    try {
        Write-EventLog -LogName "Application" -Source "SecureWindows" -EventId 1000 -EntryType $EntryType -Message $truncatedMessage -ErrorAction Stop
    }
    catch {
        $errorMsg = "Failed to write to Event Log: $_ (Message length: $($truncatedMessage.Length))"
        Write-Host "[$EntryType] $errorMsg" -ForegroundColor Red
        $errorMsg | Out-File -FilePath $logFile -Append -Encoding UTF8
    }
}

# Register script as a scheduled task for startup
function Register-StartupTask {
    param (
        [string]$TaskName = "RunGSecurityAtLogon"
    )
    
    $scriptSource = $PSCommandPath
    if (-not $scriptSource) {
        Write-Log "Error: Could not determine script path." -EntryType "Error"
        Exit-Script -ExitCode 1 -Message "Failed to register startup task due to missing script path."
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
    }
    catch {
        Write-Log "Failed to copy script to ${targetPath}: $_" -EntryType "Error"
        Exit-Script -ExitCode 1 -Message "Failed to copy script for startup task."
    }
    
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$targetPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogon
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    
    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal | Out-Null
        Write-Log "Scheduled task '$TaskName' created to run at user logon under SYSTEM."
    }
    catch {
        Write-Log "Failed to register task: $_" -EntryType "Error"
        Exit-Script -ExitCode 1 -Message "Failed to register startup task."
    }
}

# Initialize or load configuration
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
            Path = "$env:TEMP\security_rules\telemetry.json"
        }
        RetrySettings = @{
            MaxRetries = 3
            RetryDelaySeconds = 5
            UseExponentialBackoff = $true
        }
        FirewallBatchSize = 50
        MonitorIntervalSeconds = 120
    }
    
    if (Test-Path $ConfigPath) {
        try {
            $config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
            Write-Log "Loaded configuration from $ConfigPath"
            return $config
        }
        catch {
            Write-Log "Error loading configuration: $_" -EntryType "Warning"
            $defaultConfig | ConvertTo-Json -Depth 4 | Out-File -FilePath $ConfigPath -Encoding UTF8
            Write-Log "Created default configuration at $ConfigPath"
            return $defaultConfig
        }
    }
    
    $defaultConfig | ConvertTo-Json -Depth 4 | Out-File -FilePath $ConfigPath -Encoding UTF8
    Write-Log "Created default configuration at $ConfigPath"
    return $defaultConfig
}

# Validate URL accessibility with retry
function Test-Url {
    param (
        [string]$Uri,
        [int]$MaxRetries = 3,
        [int]$InitialDelay = 2
    )
    $attempt = 0
    $delay = $InitialDelay
    while ($attempt -lt $MaxRetries) {
        try {
            $response = Invoke-WebRequest -Uri $Uri -Method Head -UseBasicParsing -TimeoutSec 10
            return $response.StatusCode -eq 200
        }
        catch {
            $attempt++
            Write-Log "URL validation failed for ${Uri}: $_ (Status: $($_.Exception.Response.StatusCode))" -EntryType "Warning"
            if ($attempt -ge $MaxRetries) { return $false }
            Start-Sleep -Seconds $delay
            $delay *= 2
        }
    }
    return $false
}

# Check if rule source has been updated
function Test-RuleSourceUpdated {
    param (
        [string]$Uri,
        [string]$LocalFile,
        [int]$MaxRetries = 3
    )
    $attempt = 0
    $delay = 2
    while ($attempt -lt $MaxRetries) {
        try {
            $webRequest = Invoke-WebRequest -Uri $Uri -Method Head -UseBasicParsing -TimeoutSec 15
            $lastModified = $webRequest.Headers['Last-Modified']
            if ($lastModified) {
                $lastModifiedDate = [DateTime]::Parse($lastModified)
                if (Test-Path $LocalFile) {
                    $fileLastModified = (Get-Item $LocalFile).LastWriteTime
                    return $lastModifiedDate -gt $fileLastModified
                }
                return $true
            }
            return $true
        }
        catch {
            $attempt++
            Write-Log "Error checking update for ${Uri}: $_" -EntryType "Warning"
            if ($attempt -ge $MaxRetries) { return $true }
            Start-Sleep -Seconds $delay
            $delay *= 2
        }
    }
    return $true
}

# Get latest YARA Forge release URL
function Get-YaraForgeUrl {
    try {
        $releases = Invoke-WebRequest -Uri "https://api.github.com/repos/YARAHQ/yara-forge/releases" -UseBasicParsing
        $latest = ($releases.Content | ConvertFrom-Json)[0]
        $asset = $latest.assets | Where-Object { $_.name -match "yara-forge-.*-full\.zip|rules-full\.zip" } | Select-Object -First 1
        if ($asset) {
            Write-Log "Found YARA Forge release: $($asset.name)"
            return $asset.browser_download_url
        }
        Write-Log "No valid YARA Forge full zip found" -EntryType "Warning"
        return $null
    }
    catch {
        Write-Log "Error fetching YARA Forge release: $_" -EntryType "Warning"
        return $null
    }
}

# Count individual YARA rules
function Get-YaraRuleCount {
    param ([string]$FilePath)
    try {
        if (-not (Test-Path $FilePath)) { return 0 }
        $content = Get-Content $FilePath -Raw
        $ruleMatches = [regex]::Matches($content, 'rule\s+\w+\s*{')
        return $ruleMatches.Count
    }
    catch {
        Write-Log "Error counting rules in ${FilePath}: $_" -EntryType "Warning"
        return 0
    }
}

# Web request with retry
function Invoke-WebRequestWithRetry {
    param (
        [string]$Uri,
        [string]$OutFile,
        [int]$MaxRetries = 3,
        [int]$InitialDelay = 5,
        [switch]$UseExponentialBackoff
    )
    $attempt = 0
    $delay = $InitialDelay
    while ($attempt -lt $MaxRetries) {
        try {
            Write-Log "Downloading ${Uri} (Attempt $(${attempt}+1))..."
            Invoke-WebRequest -Uri $Uri -OutFile $OutFile -TimeoutSec 30 -UseBasicParsing
            return $true
        }
        catch {
            $attempt++
            $statusCode = if ($_.Exception.Response) { $_.Exception.Response.StatusCode } else { "Unknown" }
            Write-Log "Download attempt $attempt for ${Uri} failed: $_ (Status: $statusCode)" -EntryType "Warning"
            if ($attempt -eq $MaxRetries) { return $false }
            Start-Sleep -Seconds $delay
            if ($UseExponentialBackoff) { $delay *= 2 }
        }
    }
    return $false
}

# Download and verify rules
function Get-SecurityRules {
    param ($Config)
    $tempDir = "$env:TEMP\security_rules"
    if (-not (Test-Path $tempDir)) { New-Item -ItemType Directory -Path $tempDir -Force | Out-Null }
    $successfulSources = @()
    $rules = @{ Yara = @(); Sigma = @(); Snort = @() }

    try {
        Add-MpPreference -ExclusionPath $tempDir
        Write-Log "Added Defender exclusion for $tempDir"

        # YARA Forge rules
        $yaraForgeDir = "$tempDir\yara_forge"
        $yaraForgeZip = "$tempDir\yara_forge.zip"
        if (-not (Test-Path $yaraForgeDir)) { New-Item -ItemType Directory -Path $yaraForgeDir -Force | Out-Null }
        $yaraForgeUri = Get-YaraForgeUrl
        $yaraRuleCount = 0
        
        if ($yaraForgeUri -and (Test-Url -Uri $yaraForgeUri)) {
            if (Test-RuleSourceUpdated -Uri $yaraForgeUri -LocalFile $yaraForgeZip) {
                if (Invoke-WebRequestWithRetry -Uri $yaraForgeUri -OutFile $yaraForgeZip -UseExponentialBackoff) {
                    Start-MpScan -ScanPath $yaraForgeZip -ScanType CustomScan
                    Expand-Archive -Path $yaraForgeZip -DestinationPath $yaraForgeDir -Force
                    Write-Log "Downloaded and extracted YARA Forge rules"
                    $rules.Yara = Get-ChildItem -Path $yaraForgeDir -Recurse -Include "*.yar","*.yara" -ErrorAction SilentlyContinue
                    foreach ($file in $rules.Yara) {
                        $yaraRuleCount += Get-YaraRuleCount -FilePath $file.FullName
                    }
                    Write-Log "Found $($rules.Yara.Count) YARA Forge files with $yaraRuleCount rules"
                    $successfulSources += "YARA Forge"
                }
            } else {
                Write-Log "YARA Forge rules up to date"
                $rules.Yara = Get-ChildItem -Path $yaraForgeDir -Recurse -Include "*.yar","*.yara" -ErrorAction SilentlyContinue
                foreach ($file in $rules.Yara) {
                    $yaraRuleCount += Get-YaraRuleCount -FilePath $file.FullName
                }
                Write-Log "Found $($rules.Yara.Count) YARA Forge files with $yaraRuleCount rules"
                $successfulSources += "YARA Forge"
            }
        }

        # Yara-Rules fallback
        if (-not ($successfulSources -contains "YARA Forge") -or $yaraRuleCount -lt 10) {
            $yaraRulesDir = "$tempDir\yara_rules"
            $yaraRulesZip = "$tempDir\yara_rules.zip"
            if (-not (Test-Path $yaraRulesDir)) { New-Item -ItemType Directory -Path $yaraRulesDir -Force | Out-Null }
            $yaraRulesUri = $Config.Sources.YaraRules
            
            if (Test-Url -Uri $yaraRulesUri) {
                if (Test-RuleSourceUpdated -Uri $yaraRulesUri -LocalFile $yaraRulesZip) {
                    if (Invoke-WebRequestWithRetry -Uri $yaraRulesUri -OutFile $yaraRulesZip -UseExponentialBackoff) {
                        Start-MpScan -ScanPath $yaraRulesZip -ScanType CustomScan
                        Expand-Archive -Path $yaraRulesZip -DestinationPath $yaraRulesDir -Force
                        $yaraRulesFiles = Get-ChildItem -Path $yaraRulesDir -Recurse -Include "*.yar","*.yara" -ErrorAction SilentlyContinue
                        $rules.Yara += $yaraRulesFiles
                        $yaraRuleCount = 0
                        foreach ($file in $yaraRulesFiles) {
                            $yaraRuleCount += Get-YaraRuleCount -FilePath $file.FullName
                        }
                        Write-Log "Found $($yaraRulesFiles.Count) Yara-Rules files with $yaraRuleCount rules"
                        $successfulSources += "Yara-Rules"
                    }
                } else {
                    Write-Log "Yara-Rules up to date"
                    $rules.Yara += Get-ChildItem -Path $yaraRulesDir -Recurse -Include "*.yar","*.yara" -ErrorAction SilentlyContinue
                }
            }
        }

        # SigmaHQ rules
        $sigmaDir = "$tempDir\sigma"
        $sigmaZip = "$tempDir\sigma_rules.zip"
        if (-not (Test-Path $sigmaDir)) { New-Item -ItemType Directory -Path $sigmaDir -Force | Out-Null }
        $sigmaUri = $Config.Sources.SigmaHQ
        
        if (Test-Url -Uri $sigmaUri) {
            if (Test-RuleSourceUpdated -Uri $sigmaUri -LocalFile $sigmaZip) {
                if (Invoke-WebRequestWithRetry -Uri $sigmaUri -OutFile $sigmaZip -UseExponentialBackoff) {
                    Start-MpScan -ScanPath $sigmaZip -ScanType CustomScan
                    Expand-Archive -Path $sigmaZip -DestinationPath $sigmaDir -Force
                    Write-Log "Downloaded and extracted SigmaHQ rules"
                    $successfulSources += "SigmaHQ"
                }
            } else {
                Write-Log "SigmaHQ rules up to date"
                $successfulSources += "SigmaHQ"
            }
        }
        $sigmaRulesPath = "$sigmaDir\sigma-master\rules"
        if (Test-Path $sigmaRulesPath) {
            $rules.Sigma = Get-ChildItem -Path $sigmaRulesPath -Recurse -Include "*.yml" -Exclude "*deprecated*" -ErrorAction SilentlyContinue
            Write-Log "Found $($rules.Sigma.Count) Sigma rules"
        }

        # Snort Community rules
        $snortRules = "$tempDir\snort_community.rules"
        $snortUri = if ($SnortOinkcode) { "$($Config.Sources.SnortCommunity)?oinkcode=$SnortOinkcode" } else { $null }
        
        if ($snortUri -and (Test-Url -Uri $snortUri)) {
            if (Test-RuleSourceUpdated -Uri $snortUri -LocalFile $snortRules) {
                if (Invoke-WebRequestWithRetry -Uri $snortUri -OutFile $snortRules -UseExponentialBackoff) {
                    Start-MpScan -ScanPath $snortRules -ScanType CustomScan
                    Write-Log "Downloaded Snort Community rules"
                    $successfulSources += "Snort Community"
                    $rules.Snort += $snortRules
                }
            } else {
                Write-Log "Snort Community rules up to date"
                $successfulSources += "Snort Community"
                $rules.Snort += $snortRules
            }
        } else {
            Write-Log "No valid Snort Oinkcode provided. Get one from https://www.snort.org/users/sign_up" -EntryType "Warning"
        }

        # Emerging Threats fallback
        if (-not ($successfulSources -contains "Snort Community")) {
            $emergingRules = "$tempDir\snort_emerging.rules"
            $emergingTar = "$tempDir\emerging_rules.tar.gz"
            $emergingUri = $Config.Sources.EmergingThreats
            
            if (Test-Url -Uri $emergingUri) {
                if (Test-RuleSourceUpdated -Uri $emergingUri -LocalFile $emergingTar) {
                    if (Invoke-WebRequestWithRetry -Uri $emergingUri -OutFile $emergingTar -UseExponentialBackoff) {
                        Start-MpScan -ScanPath $emergingTar -ScanType CustomScan
                        tar -xzf $emergingTar -C $tempDir
                        if (Test-Path "$tempDir\rules") {
                            Move-Item -Path "$tempDir\rules\*.rules" -Destination $emergingRules -Force
                            Write-Log "Downloaded and extracted Emerging Threats rules"
                            $successfulSources += "Emerging Threats"
                            $rules.Snort += $emergingRules
                        }
                    }
                } else {
                    Write-Log "Emerging Threats rules up to date"
                    $successfulSources += "Emerging Threats"
                    $rules.Snort += $emergingRules
                }
            }
        }

        if ($successfulSources.Count -eq 0) {
            Write-Log "No rule sources processed successfully" -EntryType "Error"
            Exit-Script -ExitCode 1 -Message "No valid rule sources available."
        }
        
        Write-Log "Successfully processed rules from: $($successfulSources -join ', ')"
        return $rules
    }
    catch {
        Write-Log "Error in Get-SecurityRules: $_" -EntryType "Error"
        Exit-Script -ExitCode 1 -Message "Failed to download security rules."
    }
}

# Parse rules for indicators
function Parse-Rules {
    param (
        $Rules,
        $Config
    )
    $indicators = @()
    $systemFiles = $Config.ExcludedSystemFiles
    $batchSize = 1000

    # YARA parsing
    Write-Log "Parsing YARA rules..."
    foreach ($rule in $Rules.Yara) {
        try {
            if (-not (Test-Path $rule.FullName)) { continue }
            $content = Get-Content $rule.FullName -Raw
            $filenamePatterns = @(
                "(?i)meta:.*?(filename|file_name|original_filename)\s*=\s*(\""|')([^\""']+[a-zA-Z0-9_-]+\.(exe|dll|bat|ps1|scr|cmd))(\""|')",
                "(?i)\$[a-z0-9_]*\s*=\s*(\""|')([^\""']+[a-zA-Z0-9_-]+\.(exe|dll|bat|ps1|scr|cmd))(\""|')",
                "(?i)fullword\s+ascii\s+(\""|')([^\""']+[a-zA-Z0-9_-]+\.(exe|dll|bat|ps1|scr|cmd))(\""|')"
            )
            foreach ($pattern in $filenamePatterns) {
                $matches = [regex]::Matches($content, $pattern)
                foreach ($match in $matches) {
                    $fileName = [System.IO.Path]::GetFileName($match.Groups[3].Value)
                    if ($fileName -notin $systemFiles) {
                        $indicators += @{ Type = "FileName"; Value = $fileName; Source = "YARA"; RuleFile = $rule.Name }
                    }
                }
            }
            $ipPattern = "(?i)(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
            $ipMatches = [regex]::Matches($content, $ipPattern)
            foreach ($match in $ipMatches) {
                $indicators += @{ Type = "IP"; Value = $match.Value; Source = "YARA"; RuleFile = $rule.Name }
            }
        }
        catch {
            Write-Log "Error parsing YARA rule $($rule.FullName): $_" -EntryType "Warning"
        }
    }

    # Sigma parsing
    Write-Log "Parsing Sigma rules..."
    $yamlModule = Get-Module -ListAvailable -Name PowerShell-YAML
    if ($yamlModule) {
        foreach ($rule in $Rules.Sigma) {
            try {
                if (-not (Test-Path $rule.FullName)) { continue }
                $content = Get-Content $rule.FullName -Raw
                $yaml = ConvertFrom-Yaml -Yaml $content
                if ($yaml.detection) {
                    foreach ($selectionKey in $yaml.detection.Keys) {
                        $selection = $yaml.detection[$selectionKey]
                        if ($selection -is [hashtable] -or $selection -is [System.Collections.Specialized.OrderedDictionary]) {
                            foreach ($key in @('Image', 'TargetFilename', 'CommandLine', 'ParentImage', 'OriginalFileName', 'ProcessName', 'FileName')) {
                                $value = $selection[$key]
                                if ($value -is [string] -and $value -match '\.(exe|dll|bat|ps1|scr|cmd)$') {
                                    $fileName = [System.IO.Path]::GetFileName($value)
                                    if ($fileName -notin $systemFiles) {
                                        $indicators += @{ Type = "FileName"; Value = $fileName; Source = "Sigma"; RuleFile = $rule.Name }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch {
                Write-Log "Error parsing Sigma rule $($rule.FullName): $_" -EntryType "Warning"
            }
        }
    }

    # Snort parsing
    Write-Log "Parsing Snort rules..."
    foreach ($rule in $Rules.Snort) {
        try {
            if (-not (Test-Path $rule)) { continue }
            $content = Get-Content $rule -Raw
            $ipPattern = "(?i)(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
            $ipMatches = [regex]::Matches($content, $ipPattern)
            foreach ($match in $ipMatches) {
                $indicators += @{ Type = "IP"; Value = $match.Value; Source = "Snort"; RuleFile = (Split-Path $rule -Leaf) }
            }
        }
        catch {
            Write-Log ('Error parsing Snort rule ' + $rule + ': ' + $_) -EntryType "Warning"
        }
    }

    # Deduplicate indicators
    $uniqueIndicators = @()
    $indicatorGroups = $indicators | Group-Object -Property Type, Value
    foreach ($group in $indicatorGroups) {
        $uniqueIndicator = $group.Group[0].PSObject.Copy()
        $sources = ($group.Group | Select-Object -ExpandProperty Source -Unique) -join ','
        $ruleFiles = ($group.Group | Select-Object -ExpandProperty RuleFile -Unique) -join ','
        $uniqueIndicator.Source = $sources
        $uniqueIndicator.RuleFile = $ruleFiles
        $uniqueIndicators += $uniqueIndicator
    }

    $hashCount = ($uniqueIndicators | Where-Object { $_.Type -eq "Hash" }).Count
    $fileCount = ($uniqueIndicators | Where-Object { $_.Type -eq "FileName" }).Count
    $ipCount = ($uniqueIndicators | Where-Object { $_.Type -eq "IP" }).Count
    $domainCount = ($uniqueIndicators | Where-Object { $_.Type -eq "Domain" }).Count
    Write-Log "Parsed $($uniqueIndicators.Count) unique indicators (Hashes: $hashCount, Files: $fileCount, IPs: $ipCount, Domains: $domainCount)"
    
    return $uniqueIndicators
}

# Apply security rules
function Apply-SecurityRules {
    param (
        $Indicators,
        $Config
    )
    $asrRuleId = "e6db77e5-3df2-4cf1-b95a-636979351e5b"
    try {
        $asrRules = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids -ErrorAction SilentlyContinue
        $asrActions = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions -ErrorAction SilentlyContinue
        $asrIndex = if ($asrRules) { $asrRules.IndexOf($asrRuleId) } else { -1 }
        
        if ($asrIndex -ge 0) {
            if ($asrActions[$asrIndex] -ne 1) {
                Add-MpPreference -AttackSurfaceReductionRules_Ids $asrRuleId -AttackSurfaceReductionRules_Actions Enabled
                Write-Log "Enabled existing ASR rule $asrRuleId"
            }
        } else {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $asrRuleId -AttackSurfaceReductionRules_Actions Enabled
            Write-Log "Added and enabled ASR rule $asrRuleId"
        }
    }
    catch {
        Write-Log "Error configuring ASR rule: $_" -EntryType "Warning"
    }

    foreach ($indicator in ($Indicators | Where-Object { $_.Type -eq "FileName" })) {
        try {
            Write-Log "Monitoring suspicious filename: $($indicator.Value) from $($indicator.Source)"
        }
        catch {
            Write-Log "Error processing filename $($indicator.Value): $_" -EntryType "Warning"
        }
    }

    foreach ($indicator in ($Indicators | Where-Object { $_.Type -eq "IP" })) {
        try {
            New-NetFirewallRule -DisplayName "Block_GSecurity_IP_$($indicator.Value)" -Direction Outbound -Action Block -RemoteAddress $indicator.Value -ErrorAction SilentlyContinue
            Write-Log "Applied firewall rule for IP: $($indicator.Value)"
        }
        catch {
            Write-Log "Error applying firewall rule for IP $($indicator.Value): $_" -EntryType "Warning"
        }
    }
}

# Process monitoring (to be run in background job)
function Start-ProcessMonitor {
    param (
        $Indicators,
        $Config
    )
    $systemFiles = $Config.ExcludedSystemFiles
    while ($true) {
        try {
            $iteration++
            Write-Log "Monitoring active, iteration $iteration... heartbeats every $($Config.MonitorIntervalSeconds) seconds"
            $processes = Get-Process | Where-Object { $_.Path -and $_.Path -notin $systemFiles }
            foreach ($indicator in ($Indicators | Where-Object { $_.Type -eq "FileName" })) {
                $fileName = [System.IO.Path]::GetFileName($indicator.Value)
                foreach ($proc in $processes) {
                    if ($proc.Path -and ([System.IO.Path]::GetFileName($proc.Path) -eq $fileName)) {
                        Write-Log "Suspicious process detected: $($proc.Name) (PID: $($proc.Id)) Path: $($proc.Path) Source: $($indicator.Source)" -EntryType "Warning"
                        try {
                            Stop-Process -Id $proc.Id -Force -ErrorAction Stop
                            Write-Log "Terminated suspicious process: $($proc.Name) (PID: $($proc.Id))"
                        }
                        catch {
                            Write-Log "Error terminating process $($proc.Name) (PID: $($proc.Id)): $_" -EntryType "Error"
                        }
                    }
                }
            }
            Start-Sleep -Seconds $Config.MonitorIntervalSeconds
        }
        catch {
            Write-Log "Error in process monitoring: $_" -EntryType "Error"
        }
    }
}

# Generate security report
function Generate-SecurityReport {
    param (
        $Indicators,
        $Rules
    )
    $reportPath = "$env:TEMP\security_rules\GSecurity_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $report = @"
GSecurity Report
Generated: $(Get-Date)
Indicators: $($Indicators.Count)
YARA Rules: $($Rules.Yara.Count)
Sigma Rules: $($Rules.Sigma.Count)
Snort Rules: $($Rules.Snort.Count)
Details logged to: $env:TEMP\security_rules\logs
"@
    $report | Out-File -FilePath $reportPath -Encoding UTF8
    Write-Log "Generated security report at $reportPath"
}

# Main function
function Main {
    Initialize-EventLog
    $config = Initialize-Config
    Register-StartupTask
    
    $rules = Get-SecurityRules -Config $config
    $indicators = Parse-Rules -Rules $rules -Config $config
    Apply-SecurityRules -Indicators $indicators -Config $config
    Generate-SecurityReport -Indicators $indicators -Rules $rules
    
    if (-not $NoMonitor) {
        Write-Log "Starting process monitoring in background job..."
        Start-Job -ScriptBlock {
            param ($indicators, $config)
            function Write-Log {
                param (
                    [string]$Message,
                    [string]$EntryType = "Information"
                )
                $logDir = "$env:TEMP\security_rules\logs"
                $logFile = "$logDir\SecureWindows_$(Get-Date -Format 'yyyyMMdd').log"
                if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
                $logEntry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$EntryType] $Message"
                $logEntry | Out-File -FilePath $logFile -Append -Encoding UTF8
                try {
                    Write-EventLog -LogName "Application" -Source "SecureWindows" -EventId 1000 -EntryType $EntryType -Message $Message -ErrorAction Stop
                }
                catch {
                    $errorMsg = "Failed to write to Event Log: $_"
                    $errorMsg | Out-File -FilePath $logFile -Append -Encoding UTF8
                }
            }
            $systemFiles = $config.ExcludedSystemFiles
            $iteration = 0
            while ($true) {
                try {
                    $iteration++
                    Write-Log "Monitoring active, iteration $iteration... heartbeats every $($config.MonitorIntervalSeconds) seconds"
                    $processes = Get-Process | Where-Object { $_.Path -and $_.Path -notin $systemFiles }
                    foreach ($indicator in ($indicators | Where-Object { $_.Type -eq "FileName" })) {
                        $fileName = [System.IO.Path]::GetFileName($indicator.Value)
                        foreach ($proc in $processes) {
                            if ($proc.Path -and ([System.IO.Path]::GetFileName($proc.Path) -eq $fileName)) {
                                Write-Log "Suspicious process detected: $($proc.Name) (PID: $($proc.Id)) Path: $($proc.Path) Source: $($indicator.Source)" -EntryType "Warning"
                                try {
                                    Stop-Process -Id $proc.Id -Force -ErrorAction Stop
                                    Write-Log "Terminated suspicious process: $($proc.Name) (PID: $($proc.Id))"
                                }
                                catch {
                                    Write-Log "Error terminating process $($proc.Name) (PID: $($proc.Id)): $_" -EntryType "Error"
                                }
                            }
                        }
                    }
                    Start-Sleep -Seconds $config.MonitorIntervalSeconds
                }
                catch {
                    Write-Log "Error in process monitoring: $_" -EntryType "Error"
                }
            }
        } -ArgumentList $indicators, $config | Out-Null
        Write-Log "Monitoring started in background job. Script will now exit."
    } else {
        Write-Log "Monitoring disabled via -NoMonitor."
    }
    
    Exit-Script -ExitCode 0 -Message "GSecurity completed successfully."
}

# Execute main
Main