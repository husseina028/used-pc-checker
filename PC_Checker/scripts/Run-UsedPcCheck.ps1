[CmdletBinding()]
param(
    [switch]$TryElevate,
    [switch]$NoAdmin,
    [switch]$NoPause,
    [switch]$NoOpen,
    [switch]$CrystalDiskInfoOnly,
    [switch]$LaunchCrystalDiskInfo
)

$ErrorActionPreference = 'Continue'

function Test-IsAdmin {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

$Script:IsAdmin = Test-IsAdmin

if ($TryElevate -and -not $NoAdmin -and -not $Script:IsAdmin) {
    Write-Host "Requesting administrator permission for the full check..."
    try {
        $argList = '-NoProfile -ExecutionPolicy Bypass -File "' + $PSCommandPath + '"'
        Start-Process -FilePath "powershell.exe" -ArgumentList $argList -Verb RunAs -Wait
        exit 0
    } catch {
        Write-Warning "Administrator launch was cancelled or failed. Continuing in limited mode."
        Start-Sleep -Seconds 2
    }
}

$ScriptDir = Split-Path -Parent $PSCommandPath
$KitDir = Split-Path -Parent $ScriptDir
$UsbRoot = Split-Path -Parent $KitDir
$ReportsRoot = Join-Path $UsbRoot "Reports"
$safeComputer = ($env:COMPUTERNAME -replace '[^a-zA-Z0-9_-]', '_')
$stamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$ReportDir = Join-Path $ReportsRoot "$stamp-$safeComputer"
$RawDir = Join-Path $ReportDir "raw"

New-Item -ItemType Directory -Force -Path $ReportDir, $RawDir | Out-Null

$Script:Findings = @()
$Script:IsLaptop = $false

function HtmlEncode {
    param([object]$Value)
    if ($null -eq $Value) { return "" }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Add-Finding {
    param(
        [string]$Category,
        [string]$Item,
        [ValidateSet("PASS","WARN","FAIL","INFO","ERROR")]
        [string]$Status,
        [object]$Value,
        [string]$Detail,
        [string]$Action
    )

    $row = [pscustomobject]@{
        Time     = (Get-Date).ToString("s")
        Category = $Category
        Item     = $Item
        Status   = $Status
        Value    = [string]$Value
        Detail   = $Detail
        Action   = $Action
    }
    $Script:Findings += $row

    $color = "Gray"
    if ($Status -eq "PASS") { $color = "Green" }
    elseif ($Status -eq "WARN") { $color = "Yellow" }
    elseif ($Status -eq "FAIL") { $color = "Red" }
    elseif ($Status -eq "ERROR") { $color = "Magenta" }
    elseif ($Status -eq "INFO") { $color = "Cyan" }
    Write-Host ("[{0}] {1}: {2} - {3}" -f $Status, $Category, $Item, $Value) -ForegroundColor $color
}

function Save-Text {
    param([string]$Name, [object]$Text)
    $path = Join-Path $RawDir $Name
    [string]$Text | Out-File -FilePath $path -Encoding UTF8 -Width 4096
    return $path
}

function Save-Csv {
    param([string]$Name, [object]$Data)
    $path = Join-Path $RawDir $Name
    $rows = @()
    if ($null -ne $Data) {
        $rows = @($Data | Where-Object { $null -ne $_ })
    }
    if ($rows.Count -eq 0) {
        "No rows returned." | Out-File -FilePath ($path + ".txt") -Encoding UTF8
        return ($path + ".txt")
    }
    $rows | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    return $path
}

function Save-Json {
    param([string]$Name, [object]$Data)
    $path = Join-Path $RawDir $Name
    $Data | ConvertTo-Json -Depth 8 | Out-File -FilePath $path -Encoding UTF8 -Width 4096
    return $path
}

function Invoke-Check {
    param([string]$Name, [scriptblock]$Block)
    Write-Host ""
    Write-Host ("=== {0} ===" -f $Name) -ForegroundColor White
    try {
        & $Block
    } catch {
        Add-Finding "Automation" $Name "ERROR" "Check failed" $_.Exception.Message "Open raw logs and rerun as administrator if needed."
    }
}

function Invoke-WithTimeout {
    param(
        [string]$Name,
        [scriptblock]$ScriptBlock,
        [int]$TimeoutSeconds = 10
    )

    $job = $null
    try {
        $job = Start-Job -ScriptBlock $ScriptBlock -ErrorAction Stop
        $done = Wait-Job -Job $job -Timeout $TimeoutSeconds
        if (-not $done) {
            Stop-Job -Job $job -Force -ErrorAction SilentlyContinue
            throw (New-Object System.TimeoutException ("{0} timed out after {1} seconds" -f $Name, $TimeoutSeconds))
        }
        return Receive-Job -Job $job -ErrorAction Stop
    } finally {
        if ($job) {
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        }
    }
}

function Format-BytesGB {
    param([nullable[double]]$Bytes)
    if ($null -eq $Bytes) { return "" }
    return "{0:N2} GB" -f ($Bytes / 1GB)
}

function Get-WmiDate {
    param([string]$DateString)
    if ([string]::IsNullOrWhiteSpace($DateString)) { return $null }
    try { return [Management.ManagementDateTimeConverter]::ToDateTime($DateString) } catch { return $null }
}

function Get-CrystalDiskInfoExecutable {
    $cdiDir = Join-Path $UsbRoot "CrystalDiskInfo9_8_0"
    if (-not (Test-Path -LiteralPath $cdiDir)) { return $null }

    $preferred = New-Object System.Collections.Generic.List[string]
    $archValues = @($env:PROCESSOR_ARCHITECTURE, $env:PROCESSOR_ARCHITEW6432) | Where-Object { $_ }
    if (($archValues -join " ") -match "ARM64|AARCH64") { [void]$preferred.Add("DiskInfoA64.exe") }
    if ([Environment]::Is64BitOperatingSystem) { [void]$preferred.Add("DiskInfo64.exe") }
    [void]$preferred.Add("DiskInfo32.exe")
    [void]$preferred.Add("DiskInfo64.exe")
    [void]$preferred.Add("DiskInfoA64.exe")

    foreach ($name in ($preferred | Select-Object -Unique)) {
        $path = Join-Path $cdiDir $name
        if (Test-Path -LiteralPath $path) { return $path }
    }

    return $null
}

function Get-CrystalDiskInfoLineValues {
    param(
        [string]$Text,
        [string]$NamePattern
    )

    $pattern = "(?im)^\s*$NamePattern\s*:\s*(.+?)\s*$"
    return @([regex]::Matches($Text, $pattern) | ForEach-Object { $_.Groups[1].Value.Trim() } | Where-Object { $_ })
}

function Get-CrystalDiskInfoHealthTerms {
    param([string]$CdiDir)

    $terms = @{
        Good = @("Good")
        Caution = @("Caution")
        Bad = @("Bad")
        Unknown = @("Unknown")
    }

    $languageDir = Join-Path $CdiDir "CdiResource\language"
    if (Test-Path -LiteralPath $languageDir) {
        foreach ($file in @(Get-ChildItem -LiteralPath $languageDir -Filter "*.lang" -ErrorAction SilentlyContinue)) {
            try {
                foreach ($line in @(Get-Content -LiteralPath $file.FullName -Encoding UTF8 -ErrorAction Stop)) {
                    if ($line -match "^(GOOD|CAUTION|BAD|UNKNOWN)=(.+)$") {
                        $key = $Matches[1].ToUpperInvariant()
                        $value = $Matches[2].Trim().TrimEnd("!").Trim()
                        if (-not $value) { continue }

                        if ($key -eq "GOOD") { $terms.Good += $value }
                        elseif ($key -eq "CAUTION") { $terms.Caution += $value }
                        elseif ($key -eq "BAD") { $terms.Bad += $value }
                        elseif ($key -eq "UNKNOWN") { $terms.Unknown += $value }
                    }
                }
            } catch {}
        }
    }

    foreach ($key in @("Good","Caution","Bad","Unknown")) {
        $terms[$key] = @($terms[$key] | Where-Object { $_ } | Select-Object -Unique)
    }

    return $terms
}

function Test-CrystalDiskInfoHealthTerm {
    param(
        [string[]]$Values,
        [string[]]$Terms
    )

    foreach ($value in @($Values)) {
        $cleanValue = ([string]$value).Trim()
        if (-not $cleanValue) { continue }

        foreach ($term in @($Terms)) {
            $cleanTerm = ([string]$term).Trim().TrimEnd("!").Trim()
            if (-not $cleanTerm) { continue }
            if ($cleanValue.StartsWith($cleanTerm, [StringComparison]::CurrentCultureIgnoreCase)) {
                return $true
            }
        }
    }

    return $false
}

function Start-CrystalDiskInfoUi {
    param([string]$ExePath)

    if (-not $ExePath) { return }

    try {
        Start-Process -FilePath $ExePath -WorkingDirectory (Split-Path -Parent $ExePath) -ErrorAction Stop | Out-Null
        Add-Finding "Storage" "CrystalDiskInfo launcher" "INFO" "Opened" "CrystalDiskInfo was opened for manual drive inspection." "Compare the window with the saved raw CrystalDiskInfo report."
    } catch {
        Add-Finding "Storage" "CrystalDiskInfo launcher" "WARN" "Could not open" $_.Exception.Message "Open CrystalDiskInfo manually from the USB folder."
    }
}

function Invoke-CrystalDiskInfoCapture {
    param([switch]$OpenGui)

    $exe = Get-CrystalDiskInfoExecutable
    if (-not $exe) {
        Add-Finding "Storage" "CrystalDiskInfo health" "WARN" "Missing" "CrystalDiskInfo was not found at the USB root." "Make sure CrystalDiskInfo9_8_0 is beside PC_Checker on the USB."
        return
    }

    $cdiDir = Split-Path -Parent $exe
    $diskInfoSource = Join-Path $cdiDir "DiskInfo.txt"
    $targetPath = Join-Path $RawDir "crystaldiskinfo_report.txt"

    try {
        $process = Start-Process -FilePath $exe -ArgumentList "/CopyExit" -WorkingDirectory $cdiDir -WindowStyle Minimized -PassThru -ErrorAction Stop
        if (-not $process.WaitForExit(60000)) {
            try { $process.CloseMainWindow() | Out-Null } catch {}
            Start-Sleep -Seconds 2
            if (-not $process.HasExited) {
                try { $process.Kill() } catch {}
            }
            Add-Finding "Storage" "CrystalDiskInfo health" "WARN" "Timed out" "CrystalDiskInfo did not finish creating DiskInfo.txt within 60 seconds." "Open CrystalDiskInfo manually and inspect the drive health."
            if ($OpenGui) { Start-CrystalDiskInfoUi $exe }
            return
        }
    } catch {
        Add-Finding "Storage" "CrystalDiskInfo health" "WARN" "Could not run" $_.Exception.Message "Open CrystalDiskInfo manually and inspect the drive health."
        if ($OpenGui) { Start-CrystalDiskInfoUi $exe }
        return
    }

    Start-Sleep -Milliseconds 500

    if (-not (Test-Path -LiteralPath $diskInfoSource)) {
        Add-Finding "Storage" "CrystalDiskInfo health" "WARN" "No report file" "CrystalDiskInfo did not create DiskInfo.txt." "Open CrystalDiskInfo manually and inspect the drive health."
        if ($OpenGui) { Start-CrystalDiskInfoUi $exe }
        return
    }

    $sourceItem = Get-Item -LiteralPath $diskInfoSource -ErrorAction SilentlyContinue
    if (-not $sourceItem -or $sourceItem.Length -le 0) {
        Add-Finding "Storage" "CrystalDiskInfo health" "WARN" "Empty report" "CrystalDiskInfo created DiskInfo.txt, but it was empty." "Open CrystalDiskInfo manually and inspect the drive health."
        if ($OpenGui) { Start-CrystalDiskInfoUi $exe }
        return
    }

    try {
        Copy-Item -LiteralPath $diskInfoSource -Destination $targetPath -Force -ErrorAction Stop
        $text = Get-Content -LiteralPath $targetPath -Raw -Encoding UTF8 -ErrorAction Stop
    } catch {
        Add-Finding "Storage" "CrystalDiskInfo health" "WARN" "Report copy failed" $_.Exception.Message "Open the DiskInfo.txt file in the CrystalDiskInfo folder manually."
        if ($OpenGui) { Start-CrystalDiskInfoUi $exe }
        return
    }

    $models = @(Get-CrystalDiskInfoLineValues $text "Model")
    $serials = @(Get-CrystalDiskInfoLineValues $text "Serial Number")
    $healthValues = @(Get-CrystalDiskInfoLineValues $text "Health Status")
    $temperatures = @(Get-CrystalDiskInfoLineValues $text "Temperature")
    $powerOnHours = @(Get-CrystalDiskInfoLineValues $text "Power On Hours")
    $powerOnCounts = @(Get-CrystalDiskInfoLineValues $text "Power On Count")
    $hostWrites = @(Get-CrystalDiskInfoLineValues $text "(?:Total Host Writes|Host Writes)")
    $healthTerms = Get-CrystalDiskInfoHealthTerms $cdiDir

    $rowCount = [int]((@($models.Count, $serials.Count, $healthValues.Count, $temperatures.Count, $powerOnHours.Count, $powerOnCounts.Count, $hostWrites.Count) | Measure-Object -Maximum).Maximum)
    if ($rowCount -gt 0) {
        $rows = for ($i = 0; $i -lt $rowCount; $i++) {
            $model = if ($i -lt $models.Count) { $models[$i] } else { "" }
            $serial = if ($i -lt $serials.Count) { $serials[$i] } else { "" }
            $health = if ($i -lt $healthValues.Count) { $healthValues[$i] } else { "" }
            $temperature = if ($i -lt $temperatures.Count) { $temperatures[$i] } else { "" }
            $hours = if ($i -lt $powerOnHours.Count) { $powerOnHours[$i] } else { "" }
            $count = if ($i -lt $powerOnCounts.Count) { $powerOnCounts[$i] } else { "" }
            $writes = if ($i -lt $hostWrites.Count) { $hostWrites[$i] } else { "" }
            [pscustomobject]@{
                Model = $model
                SerialNumber = $serial
                HealthStatus = $health
                Temperature = $temperature
                PowerOnHours = $hours
                PowerOnCount = $count
                HostWrites = $writes
            }
        }
        Save-Csv "crystaldiskinfo_summary.csv" $rows | Out-Null
    }

    $status = "INFO"
    $value = "Report captured"
    $action = "Review raw\crystaldiskinfo_report.txt for full SMART details."
    if ($healthValues.Count -gt 0) {
        $value = (($healthValues | Select-Object -Unique) -join "; ")
        if (Test-CrystalDiskInfoHealthTerm $healthValues $healthTerms.Bad) {
            $status = "FAIL"
            $action = "Treat this as a storage red flag. Do not buy unless the drive is replaced and retested."
        } elseif ((Test-CrystalDiskInfoHealthTerm $healthValues $healthTerms.Caution) -or (Test-CrystalDiskInfoHealthTerm $healthValues $healthTerms.Unknown)) {
            $status = "WARN"
            $action = "Open CrystalDiskInfo and inspect the reported drive before buying."
        } elseif (Test-CrystalDiskInfoHealthTerm $healthValues $healthTerms.Good) {
            $status = "PASS"
            $action = "Keep the raw CrystalDiskInfo report with the sales record."
        } else {
            $status = "INFO"
            $action = "Open raw\crystaldiskinfo_report.txt or the CrystalDiskInfo window and inspect the health text manually."
        }
    } else {
        $value = "Captured, not parsed"
        $action = "Open raw\crystaldiskinfo_report.txt or the CrystalDiskInfo window and inspect health manually."
    }

    $driveText = if ($models.Count -gt 0) { "Drive(s): {0}." -f (($models | Select-Object -Unique) -join "; ") } else { "Drive model lines were not parsed." }
    Add-Finding "Storage" "CrystalDiskInfo health" $status $value "$driveText Raw CrystalDiskInfo output saved as raw\crystaldiskinfo_report.txt." $action

    if ($OpenGui) { Start-CrystalDiskInfoUi $exe }
}

try { Start-Transcript -Path (Join-Path $ReportDir "RunLog.txt") -Force | Out-Null } catch {}

Write-Host ""
Write-Host "Used PC Checker" -ForegroundColor White
Write-Host ("Report folder: {0}" -f $ReportDir)
Write-Host ""

$privStatus = if ($Script:IsAdmin) { "PASS" } else { "WARN" }
$privValue = if ($Script:IsAdmin) { "Administrator" } else { "Limited user" }
$privDetail = if ($Script:IsAdmin) { "Full diagnostic permissions available." } else { "Some storage, security, and event log checks may be incomplete." }
Add-Finding "Run" "Privilege level" $privStatus $privValue $privDetail "Use option 1 in Run_PC_Checker.bat for the fullest report."

if (-not $CrystalDiskInfoOnly) {

Invoke-Check "System identity" {
    $computer = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $baseboard = Get-CimInstance Win32_BaseBoard -ErrorAction SilentlyContinue
    $enclosure = Get-CimInstance Win32_SystemEnclosure -ErrorAction SilentlyContinue

    if (-not $computer -and -not $bios -and -not $os) {
        Add-Finding "System" "Identity data" "WARN" "Unavailable" "Windows did not allow WMI/CIM identity reads in this session." "Rerun option 1 as administrator, then compare the model and serial manually."
        return
    }

    Save-Json "system_identity.json" ([pscustomobject]@{
        ComputerSystem = $computer
        Bios = $bios
        OperatingSystem = $os
        BaseBoard = $baseboard
        Enclosure = $enclosure
    }) | Out-Null

    $chassisTypes = @($enclosure.ChassisTypes)
    $portableCodes = @(8,9,10,11,12,14,18,21,30,31,32)
    foreach ($code in $chassisTypes) {
        if ($portableCodes -contains [int]$code) { $Script:IsLaptop = $true }
    }

    if ($computer) {
        Add-Finding "System" "Model" "INFO" ("{0} {1}" -f $computer.Manufacturer, $computer.Model) "Compare this with the seller listing." "If the listing claims a different model, verify before buying."
    } else {
        Add-Finding "System" "Model" "WARN" "Unavailable" "Windows did not return Win32_ComputerSystem data." "Check the model in Settings, BIOS, or the chassis label."
    }

    if ($bios) {
        $serial = [string]$bios.SerialNumber
        if ([string]::IsNullOrWhiteSpace($serial) -or $serial -match "To be filled|Default|System Serial") {
            Add-Finding "System" "BIOS serial" "WARN" $serial "Serial number is missing or generic." "Check the chassis sticker and BIOS setup manually."
        } else {
            Add-Finding "System" "BIOS serial" "PASS" $serial "Serial number is present." "Compare with the chassis and seller listing."
        }
    } else {
        Add-Finding "System" "BIOS serial" "WARN" "Unavailable" "Windows did not return BIOS data." "Check the serial number in BIOS and on the chassis label."
    }

    if ($os) {
        $installDate = Get-WmiDate $os.InstallDate
        if ($installDate) {
            $ageDays = [math]::Round(((Get-Date) - $installDate).TotalDays, 1)
            $status = if ($ageDays -lt 7) { "WARN" } else { "PASS" }
            $detail = if ($ageDays -lt 7) { "Very recent Windows install can hide older reliability history." } else { "Windows install is not brand new." }
            Add-Finding "System" "Windows install age" $status ("{0} days" -f $ageDays) $detail "A fresh install is not automatically bad, but inspect hardware more carefully."
        }

        $bootTime = Get-WmiDate $os.LastBootUpTime
        Add-Finding "System" "Windows version" "INFO" ("{0} build {1}" -f $os.Caption, $os.BuildNumber) ("Last boot: {0}" -f $bootTime) "Confirm this is the edition you expect."
    } else {
        Add-Finding "System" "Windows version" "WARN" "Unavailable" "Windows did not return operating system data." "Check Settings > System > About manually."
    }
}

Invoke-Check "CPU, RAM, and GPU" {
    $cpu = @(Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue)
    $memory = @(Get-CimInstance Win32_PhysicalMemory -ErrorAction SilentlyContinue)
    $gpu = @(Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue)

    Save-Csv "cpu.csv" $cpu | Out-Null
    Save-Csv "memory_modules.csv" ($memory | Select-Object BankLabel, DeviceLocator, Manufacturer, PartNumber, SerialNumber, Capacity, Speed, ConfiguredClockSpeed) | Out-Null
    Save-Csv "gpu.csv" ($gpu | Select-Object Name, DriverVersion, AdapterRAM, Status, VideoProcessor, CurrentHorizontalResolution, CurrentVerticalResolution) | Out-Null

    foreach ($p in @($cpu)) {
        $logical = [int]$p.NumberOfLogicalProcessors
        $cpuStatus = if ($logical -lt 4) { "WARN" } else { "INFO" }
        Add-Finding "CPU" $p.Name $cpuStatus ("{0} cores / {1} threads" -f $p.NumberOfCores, $p.NumberOfLogicalProcessors) "Low thread count can feel slow on modern Windows." "Judge this against your workload and price."
    }

    if ($cpu.Count -eq 0) {
        Add-Finding "CPU" "Processor data" "WARN" "Unavailable" "Windows did not allow CPU WMI/CIM reads in this session." "Rerun option 1 as administrator or check Task Manager manually."
    }

    if ($memory.Count -gt 0) {
        $totalRam = ($memory | Measure-Object -Property Capacity -Sum).Sum
        $ramGb = [math]::Round($totalRam / 1GB, 2)
        $ramStatus = if ($ramGb -lt 4) { "FAIL" } elseif ($ramGb -lt 8) { "WARN" } else { "PASS" }
        $ramDetail = if ($ramGb -lt 8) { "Less than 8 GB is limiting for modern Windows use." } else { "RAM amount is acceptable for normal use." }
        Add-Finding "RAM" "Installed memory" $ramStatus ("{0:N2} GB across {1} module(s)" -f $ramGb, $memory.Count) $ramDetail "Check whether RAM is upgradeable on this model."
    } else {
        Add-Finding "RAM" "Installed memory" "WARN" "Unavailable" "Windows did not allow memory WMI/CIM reads in this session." "Check Task Manager or System Information manually."
    }

    if ($gpu.Count -eq 0) {
        Add-Finding "GPU" "Display adapters" "WARN" "None detected" "Windows did not return a video controller." "Check Device Manager and display output manually."
    } else {
        foreach ($v in $gpu) {
            $gpuStatus = if ($v.Status -and $v.Status -ne "OK") { "WARN" } else { "INFO" }
            Add-Finding "GPU" $v.Name $gpuStatus $v.DriverVersion ("Status: {0}" -f $v.Status) "Run the screen test and check for flicker, artifacts, or driver crashes."
        }
    }
}

Invoke-Check "Battery health" {
    $batteries = @(Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue)
    Save-Csv "win32_battery.csv" $batteries | Out-Null

    if ($batteries.Count -eq 0) {
        $status = if ($Script:IsLaptop) { "FAIL" } else { "INFO" }
        Add-Finding "Battery" "Battery detected" $status "No battery reported" "Windows did not expose a laptop battery." "If this is a laptop, check Device Manager and verify the battery is not missing or disabled."
    } else {
        foreach ($b in $batteries) {
            Add-Finding "Battery" ("Battery {0}" -f $b.DeviceID) "INFO" ("Status code {0}, estimated charge {1}%" -f $b.BatteryStatus, $b.EstimatedChargeRemaining) "Windows battery object is present." "Use the health percentage below for the buying decision."
        }
    }

    $batteryReport = Join-Path $ReportDir "BatteryReport.html"
    $batteryOutput = & powercfg /batteryreport /output $batteryReport 2>&1 | Out-String
    Save-Text "powercfg_batteryreport_output.txt" $batteryOutput | Out-Null

    if (-not (Test-Path $batteryReport)) {
        Add-Finding "Battery" "Battery report" "WARN" "Not generated" "powercfg did not create BatteryReport.html." "Rerun as administrator or check whether this is a desktop/no-battery device."
        return
    }

    Add-Finding "Battery" "Battery report file" "INFO" "BatteryReport.html" "Full Windows battery report saved next to Summary.html." "Open the report for charge history and battery usage details."

    $html = Get-Content -Path $batteryReport -Raw -ErrorAction Stop
    $plain = $html -replace '(?is)<script.*?</script>', ' '
    $plain = $plain -replace '(?is)<style.*?</style>', ' '
    $plain = $plain -replace '<[^>]+>', ' '
    $plain = [System.Net.WebUtility]::HtmlDecode($plain)
    $plain = $plain -replace '\s+', ' '

    $design = $null
    $full = $null
    $cycle = $null

    if ($plain -match '(?i)DESIGN CAPACITY\s+([\d,]+)\s+mWh') {
        $design = [int64](($Matches[1]) -replace ',', '')
    }
    if ($plain -match '(?i)FULL CHARGE CAPACITY\s+([\d,]+)\s+mWh') {
        $full = [int64](($Matches[1]) -replace ',', '')
    }
    if ($plain -match '(?i)CYCLE COUNT\s+([\d,]+)') {
        $cycle = [int64](($Matches[1]) -replace ',', '')
    }

    if ($design -and $full -and $design -gt 0) {
        $health = [math]::Round(($full / $design) * 100, 1)
        $healthStatus = if ($health -lt 70) { "FAIL" } elseif ($health -lt 80) { "WARN" } else { "PASS" }
        $healthDetail = "Design capacity: $design mWh. Full charge capacity: $full mWh."
        Add-Finding "Battery" "Battery health" $healthStatus ("{0}%" -f $health) $healthDetail "Below 80% means battery replacement cost should affect the price."
    } else {
        Add-Finding "Battery" "Battery health" "WARN" "Could not parse" "Battery report did not expose design and full charge capacities in the expected format." "Open BatteryReport.html manually."
    }

    if ($cycle -ne $null) {
        $cycleStatus = if ($cycle -gt 900) { "FAIL" } elseif ($cycle -gt 500) { "WARN" } else { "PASS" }
        Add-Finding "Battery" "Cycle count" $cycleStatus $cycle "Higher cycles usually mean more battery wear." "Use this together with battery health percentage."
    } else {
        Add-Finding "Battery" "Cycle count" "INFO" "Not reported" "Many laptops do not expose cycle count to Windows." "Rely on battery health and real runtime testing."
    }
}

Invoke-Check "Storage health" {
    $diskDrives = @(Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue)
    Save-Csv "disk_drives.csv" ($diskDrives | Select-Object Model, SerialNumber, FirmwareRevision, InterfaceType, MediaType, Status, Size, PNPDeviceID) | Out-Null

    $badDisk = @($diskDrives | Where-Object { $_.Status -and $_.Status -ne "OK" })
    if ($diskDrives.Count -eq 0) {
        Add-Finding "Storage" "Win32 disk status" "WARN" "Unavailable" "Windows did not allow Win32_DiskDrive reads in this session." "Rerun option 1 as administrator or check Disk Management and drive SMART manually."
    } elseif ($badDisk.Count -gt 0) {
        Add-Finding "Storage" "Win32 disk status" "FAIL" ("{0} bad disk(s)" -f $badDisk.Count) "At least one disk does not report OK." "Avoid buying unless the disk is replaced and retested."
    } else {
        Add-Finding "Storage" "Win32 disk status" "PASS" ("{0} disk(s) OK" -f $diskDrives.Count) "All disks reported OK through Win32_DiskDrive." "Still check SMART and event logs below."
    }

    if (Get-Command Get-PhysicalDisk -ErrorAction SilentlyContinue) {
        $physical = @()
        try {
            $physical = @(Get-PhysicalDisk -ErrorAction Stop)
        } catch {
            Add-Finding "Storage" "Physical disk health" "WARN" "Unavailable" $_.Exception.Message "Rerun option 1 as administrator or check storage health manually."
        }
        Save-Csv "physical_disks.csv" ($physical | Select-Object FriendlyName, SerialNumber, MediaType, HealthStatus, OperationalStatus, Size, BusType, FirmwareVersion) | Out-Null
        $unhealthy = @($physical | Where-Object { $_.HealthStatus -and $_.HealthStatus -ne "Healthy" })
        if ($unhealthy.Count -gt 0) {
            Add-Finding "Storage" "Physical disk health" "FAIL" ("{0} unhealthy disk(s)" -f $unhealthy.Count) "Windows Storage reports an unhealthy disk." "Do not buy without a replacement plan."
        } elseif ($physical.Count -gt 0) {
            Add-Finding "Storage" "Physical disk health" "PASS" "Healthy" "Windows Storage reports healthy physical disks." "Continue checking event logs for hidden storage errors."
        }

        $hasSsd = @($physical | Where-Object { $_.MediaType -match "SSD|SCM" }).Count -gt 0
        $onlyHdd = ($physical.Count -gt 0 -and -not $hasSsd)
        if ($onlyHdd) {
            Add-Finding "Storage" "SSD presence" "WARN" "No SSD detected" "A hard-drive-only laptop will feel much slower and is more shock-sensitive." "Price should reflect the need for an SSD upgrade."
        } elseif ($hasSsd) {
            Add-Finding "Storage" "SSD presence" "PASS" "SSD detected" "At least one solid-state drive is present." "Confirm capacity is enough for your use."
        }

        $reliability = @()
        foreach ($pd in $physical) {
            try {
                $counter = $pd | Get-StorageReliabilityCounter -ErrorAction Stop
                $reliability += $counter
            } catch {}
        }
        if ($reliability.Count -gt 0) {
            Save-Csv "storage_reliability_counters.csv" $reliability | Out-Null
            $hot = @($reliability | Where-Object { $_.Temperature -and $_.Temperature -gt 65 })
            if ($hot.Count -gt 0) {
                Add-Finding "Storage" "Drive temperature" "WARN" ("{0} hot drive(s)" -f $hot.Count) "One or more drives report temperature above 65 C." "Check airflow and run longer tests before buying."
            } else {
                Add-Finding "Storage" "Drive temperature" "INFO" "Counters saved" "Storage reliability counters were saved in raw data." "Review raw CSV if you suspect heavy SSD wear."
            }
        }
    }

    try {
        $smart = @(Get-CimInstance -Namespace root\wmi -ClassName MSStorageDriver_FailurePredictStatus -ErrorAction Stop)
        Save-Csv "smart_failure_predict_status.csv" $smart | Out-Null
        $predictFail = @($smart | Where-Object { $_.PredictFailure })
        if ($predictFail.Count -gt 0) {
            Add-Finding "Storage" "SMART failure prediction" "FAIL" "PredictFailure=True" "The drive predicts failure." "Do not buy unless replacing the drive immediately."
        } elseif ($smart.Count -gt 0) {
            Add-Finding "Storage" "SMART failure prediction" "PASS" "No predicted failure" "Windows SMART failure prediction did not flag a drive." "SMART cannot catch every disk problem, so check event logs too."
        }
    } catch {
        Add-Finding "Storage" "SMART failure prediction" "WARN" "Unavailable" $_.Exception.Message "Rerun as administrator or use the drive maker's diagnostic if storage condition matters."
    }

    $fixedVolumes = @(Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue)
    Save-Csv "fixed_volumes.csv" ($fixedVolumes | Select-Object DeviceID, VolumeName, FileSystem, Size, FreeSpace) | Out-Null
    foreach ($vol in $fixedVolumes) {
        if ($vol.Size -gt 0) {
            $freePct = [math]::Round(($vol.FreeSpace / $vol.Size) * 100, 1)
            $volStatus = if ($freePct -lt 10) { "WARN" } else { "INFO" }
            Add-Finding "Storage" ("Volume {0}" -f $vol.DeviceID) $volStatus ("{0}% free" -f $freePct) ("{0} free of {1}" -f (Format-BytesGB $vol.FreeSpace), (Format-BytesGB $vol.Size)) "Low free space can hide update or performance issues."
        }
    }
}

Invoke-Check "Device Manager" {
    if (-not (Get-Command Get-PnpDevice -ErrorAction SilentlyContinue)) {
        Add-Finding "Devices" "Get-PnpDevice" "WARN" "Unavailable" "This Windows version or PowerShell session does not expose Get-PnpDevice." "Open Device Manager manually and check for warning icons."
        return
    }

    $devices = @(Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue)
    Save-Csv "pnp_devices_present.csv" ($devices | Select-Object Status, Class, FriendlyName, InstanceId, Problem) | Out-Null
    $problem = @($devices | Where-Object { $_.Status -and $_.Status -ne "OK" })
    Save-Csv "pnp_problem_devices.csv" ($problem | Select-Object Status, Class, FriendlyName, InstanceId, Problem) | Out-Null

    if ($problem.Count -gt 0) {
        Add-Finding "Devices" "Problem devices" "WARN" ("{0} present device(s)" -f $problem.Count) "One or more present devices are not OK." "Open raw pnp_problem_devices.csv and Device Manager before buying."
    } else {
        Add-Finding "Devices" "Problem devices" "PASS" "None" "All present PnP devices report OK." "Still test ports, camera, keyboard, and touchpad manually."
    }

    $classes = @("Camera","Image","Bluetooth","Net","Media","USB")
    foreach ($class in $classes) {
        $rows = @($devices | Where-Object { $_.Class -eq $class })
        if ($rows.Count -gt 0) {
            Add-Finding "Devices" ("{0} devices" -f $class) "INFO" $rows.Count "Device list saved in raw data." "Manually test the devices you care about."
        }
    }
}

Invoke-Check "Network, audio, camera" {
    if (Get-Command Get-NetAdapter -ErrorAction SilentlyContinue) {
        $adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue)
        Save-Csv "network_adapters.csv" ($adapters | Select-Object Name, InterfaceDescription, Status, LinkSpeed, MacAddress, NdisPhysicalMedium) | Out-Null
        $wifi = @($adapters | Where-Object { $_.Name -match "Wi-?Fi|Wireless|WLAN" -or $_.InterfaceDescription -match "Wi-?Fi|Wireless|802\.11|WLAN" })
        if ($Script:IsLaptop -and $wifi.Count -eq 0) {
            Add-Finding "Network" "Wi-Fi adapter" "WARN" "Not detected" "No Wi-Fi adapter matched common names." "Check Device Manager and test Wi-Fi manually."
        } elseif ($wifi.Count -gt 0) {
            Add-Finding "Network" "Wi-Fi adapter" "INFO" ($wifi.InterfaceDescription -join "; ") "Wi-Fi adapter detected." "Connect to a network before buying."
        }
    }

    $sound = @(Get-CimInstance Win32_SoundDevice -ErrorAction SilentlyContinue)
    Save-Csv "sound_devices.csv" ($sound | Select-Object Name, Manufacturer, Status, DeviceID) | Out-Null
    $badSound = @($sound | Where-Object { $_.Status -and $_.Status -ne "OK" })
    if ($sound.Count -eq 0) {
        Add-Finding "Audio" "Sound device" "WARN" "None detected" "Windows did not return an audio device." "Test speakers, microphone, and headphone jack manually."
    } elseif ($badSound.Count -gt 0) {
        Add-Finding "Audio" "Sound device status" "WARN" ("{0} not OK" -f $badSound.Count) "One or more sound devices are not OK." "Test audio manually."
    } else {
        Add-Finding "Audio" "Sound devices" "PASS" $sound.Count "Audio devices report OK." "Use the manual tester for left/right speaker check."
    }
}

Invoke-Check "Security and firmware" {
    if (Get-Command Get-Tpm -ErrorAction SilentlyContinue) {
        try {
            $tpm = Get-Tpm -ErrorAction Stop
            Save-Json "tpm.json" $tpm | Out-Null
            if ($tpm.TpmPresent -and $tpm.TpmReady) {
                Add-Finding "Security" "TPM" "PASS" "Present and ready" "TPM is usable." "Useful for Windows 11 and device encryption."
            } elseif ($tpm.TpmPresent) {
                Add-Finding "Security" "TPM" "WARN" "Present but not ready" "TPM exists but is not ready." "Check BIOS settings before buying if Windows 11 support matters."
            } else {
                Add-Finding "Security" "TPM" "WARN" "Not present" "TPM was not detected." "Windows 11 support or encryption may be limited."
            }
        } catch {
            Add-Finding "Security" "TPM" "WARN" "Unavailable" $_.Exception.Message "Check BIOS/UEFI manually."
        }
    }

    try {
        $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop
        $sbStatus = if ($secureBoot) { "PASS" } else { "WARN" }
        Add-Finding "Security" "Secure Boot" $sbStatus $secureBoot "Secure Boot state returned by UEFI." "If disabled, check whether it can be enabled in BIOS."
    } catch {
        Add-Finding "Security" "Secure Boot" "INFO" "Unavailable" $_.Exception.Message "May be legacy BIOS, unsupported, or require admin."
    }

    if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
        try {
            Write-Host "Checking BitLocker status with a 10 second timeout..." -ForegroundColor DarkGray
            $bitlocker = @(Invoke-WithTimeout -Name "BitLocker check" -TimeoutSeconds 10 -ScriptBlock {
                Import-Module BitLocker -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                Get-BitLockerVolume -ErrorAction Stop
            })
            Save-Csv "bitlocker_volumes.csv" ($bitlocker | Select-Object MountPoint, VolumeStatus, ProtectionStatus, LockStatus, EncryptionPercentage) | Out-Null
            $locked = @($bitlocker | Where-Object { $_.LockStatus -ne "Unlocked" })
            if ($locked.Count -gt 0) {
                Add-Finding "Security" "BitLocker" "WARN" ("{0} locked volume(s)" -f $locked.Count) "One or more BitLocker volumes are locked." "Do not buy without the recovery key and ownership transfer."
            } else {
                Add-Finding "Security" "BitLocker" "INFO" "Checked" "BitLocker volume status saved." "If protection is on, make sure you get the recovery key."
            }
        } catch {
            $status = if ($_.Exception -is [System.TimeoutException]) { "WARN" } else { "INFO" }
            $action = if ($_.Exception -is [System.TimeoutException]) { "The check was skipped so the report could continue. Open Settings > Privacy & security > Device encryption or Control Panel > BitLocker manually." } else { "Check Windows Settings manually if encryption matters." }
            Add-Finding "Security" "BitLocker" $status "Unavailable or timed out" $_.Exception.Message $action
        }
    }

    try {
        $license = @(Get-CimInstance SoftwareLicensingProduct -ErrorAction Stop | Where-Object { $_.PartialProductKey -and $_.Name -match "Windows" })
        Save-Csv "windows_license.csv" ($license | Select-Object Name, Description, LicenseStatus, PartialProductKey) | Out-Null
        $licensed = @($license | Where-Object { $_.LicenseStatus -eq 1 })
        if ($licensed.Count -gt 0) {
            Add-Finding "Windows" "Activation" "PASS" "Licensed" "Windows reports an activated license." "Still check Settings > Activation if the seller recently changed hardware."
        } else {
            Add-Finding "Windows" "Activation" "WARN" "Not confirmed" "Windows activation was not confirmed by SoftwareLicensingProduct." "Open Settings > System > Activation before buying."
        }
    } catch {
        Add-Finding "Windows" "Activation" "WARN" "Unavailable" $_.Exception.Message "Check activation manually."
    }

    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        try {
            $defender = Get-MpComputerStatus -ErrorAction Stop
            Save-Json "defender_status.json" $defender | Out-Null
            if ($defender.AntivirusEnabled -and $defender.RealTimeProtectionEnabled) {
                Add-Finding "Security" "Defender" "PASS" "Enabled" "Microsoft Defender antivirus and real-time protection are enabled." "Good baseline; still scan after purchase."
            } else {
                Add-Finding "Security" "Defender" "WARN" "Disabled or limited" "Defender antivirus or real-time protection is off." "Do not trust the install; wipe/reinstall after purchase."
            }
        } catch {
            Add-Finding "Security" "Defender" "INFO" "Unavailable" $_.Exception.Message "May be managed by another antivirus."
        }
    }
}

Invoke-Check "Thermal sensors" {
    try {
        $thermal = @(Get-CimInstance -Namespace root\wmi -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction Stop)
        $thermalRows = foreach ($t in $thermal) {
            [pscustomobject]@{
                InstanceName = $t.InstanceName
                Celsius = [math]::Round(($t.CurrentTemperature / 10) - 273.15, 1)
                CriticalTripPointC = if ($t.CriticalTripPoint) { [math]::Round(($t.CriticalTripPoint / 10) - 273.15, 1) } else { $null }
            }
        }
        Save-Csv "thermal_zones.csv" $thermalRows | Out-Null
        if ($thermalRows.Count -eq 0) {
            Add-Finding "Thermals" "ACPI sensors" "INFO" "No rows" "Windows did not expose ACPI thermal zones." "Use fan noise, chassis heat, and a longer stress test if needed."
        } else {
            $hot = @($thermalRows | Where-Object { $_.Celsius -gt 85 })
            if ($hot.Count -gt 0) {
                Add-Finding "Thermals" "Temperature" "WARN" ("{0} zone(s) above 85 C" -f $hot.Count) "ACPI thermal zones report high temperature." "Let the laptop cool, retest, and consider walking away if heat returns."
            } else {
                Add-Finding "Thermals" "ACPI sensors" "INFO" ("{0} zone(s)" -f $thermalRows.Count) "Thermal zone data saved." "ACPI readings are often incomplete; still check fan noise and heat manually."
            }
        }
    } catch {
        Add-Finding "Thermals" "ACPI sensors" "INFO" "Unavailable" $_.Exception.Message "Many laptops do not expose useful thermal data to Windows."
    }
}

Invoke-Check "Event log red flags" {
    $since = (Get-Date).AddDays(-14)
    try {
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = "System"; Level = 1,2; StartTime = $since } -MaxEvents 1000 -ErrorAction Stop)
        $eventRows = $events | Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, @{Name="Message"; Expression={ ([string]$_.Message).Substring(0, [Math]::Min(500, ([string]$_.Message).Length)) }}
        Save-Csv "system_critical_errors_last14days.csv" $eventRows | Out-Null

        $critical = @($events | Where-Object { $_.Level -eq 1 })
        $whea = @($events | Where-Object { $_.ProviderName -match "WHEA" })
        $disk = @($events | Where-Object { $_.ProviderName -match "disk|ntfs|stornvme|storahci|iaStor|volmgr" })
        $bugcheck = @($events | Where-Object { $_.ProviderName -match "BugCheck|WER-SystemErrorReporting" -or $_.Id -eq 1001 })
        $kernelPower = @($events | Where-Object { $_.ProviderName -match "Kernel-Power" -and $_.Id -eq 41 })
        $display = @($events | Where-Object { $_.ProviderName -match "Display|nvlddmkm|amdwddmg|igfx" })

        if ($whea.Count -gt 0) {
            Add-Finding "Events" "WHEA hardware errors" "FAIL" $whea.Count "WHEA events can indicate CPU, RAM, motherboard, PCIe, or power instability." "Strong red flag. Do not buy without deeper stress testing."
        } else {
            Add-Finding "Events" "WHEA hardware errors" "PASS" "0" "No WHEA hardware errors found in System log search window." "This reduces risk but does not prove hardware is perfect."
        }

        if ($disk.Count -gt 0) {
            Add-Finding "Events" "Disk/storage errors" "FAIL" $disk.Count "Storage-related system errors were found." "Avoid buying unless the storage issue is understood and fixed."
        } else {
            Add-Finding "Events" "Disk/storage errors" "PASS" "0" "No disk/storage errors found in the search window." "Still consider drive age and SMART data."
        }

        if ($bugcheck.Count -gt 0) {
            Add-Finding "Events" "Blue screen indicators" "WARN" $bugcheck.Count "BugCheck or system error reporting events were found." "Ask why it crashed and run stress tests before buying."
        } else {
            Add-Finding "Events" "Blue screen indicators" "PASS" "0" "No BSOD indicators found in the search window." "A fresh Windows install can erase older history."
        }

        if ($kernelPower.Count -gt 0) {
            Add-Finding "Events" "Unexpected shutdowns" "WARN" $kernelPower.Count "Kernel-Power 41 means Windows did not shut down cleanly." "Could be dead battery, seller hard power-off, or instability. Investigate pattern."
        }

        if ($display.Count -gt 0) {
            Add-Finding "Events" "Display driver errors" "WARN" $display.Count "Display/GPU-related errors were found." "Run the screen test and check for flicker, artifacts, or driver resets."
        }

        if ($critical.Count -gt 0) {
            Add-Finding "Events" "Critical events total" "WARN" $critical.Count "Critical System events found in the last 14 days." "Open raw event CSV and inspect timing."
        } else {
            Add-Finding "Events" "Critical events total" "PASS" "0" "No critical System events found in the last 14 days." "Good sign if Windows was not freshly reinstalled."
        }
    } catch {
        Add-Finding "Events" "System event log" "WARN" "Unavailable" $_.Exception.Message "Rerun as administrator or inspect Event Viewer manually."
    }

    try {
        $reliability = @(Get-CimInstance Win32_ReliabilityRecords -ErrorAction Stop | Select-Object -First 200)
        Save-Csv "reliability_records_latest.csv" ($reliability | Select-Object TimeGenerated, SourceName, EventIdentifier, ProductName, Message) | Out-Null
        if ($reliability.Count -gt 0) {
            Add-Finding "Events" "Reliability Monitor records" "INFO" $reliability.Count "Latest reliability records saved." "Look for repeated app/hardware failures."
        }
    } catch {
        Add-Finding "Events" "Reliability Monitor" "INFO" "Unavailable" $_.Exception.Message "Reliability data is sometimes disabled or cleared."
    }
}

Invoke-Check "Windows updates" {
    try {
        $hotfixes = @(Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending)
        Save-Csv "hotfixes.csv" ($hotfixes | Select-Object HotFixID, Description, InstalledOn, InstalledBy) | Out-Null
        $latest = $hotfixes | Where-Object { $_.InstalledOn } | Select-Object -First 1
        if ($latest) {
            $days = [math]::Round(((Get-Date) - [datetime]$latest.InstalledOn).TotalDays, 1)
            $updateStatus = if ($days -gt 90) { "WARN" } else { "INFO" }
            Add-Finding "Windows" "Last hotfix" $updateStatus ("{0}, {1} days ago" -f $latest.HotFixID, $days) "Patch history saved." "Old patch state is usually fixable, but can signal neglect."
        }
    } catch {
        Add-Finding "Windows" "Hotfix history" "INFO" "Unavailable" $_.Exception.Message "Check Windows Update manually."
    }
}

}

Invoke-Check "CrystalDiskInfo SMART report" {
    Invoke-CrystalDiskInfoCapture -OpenGui:$LaunchCrystalDiskInfo
}

$findingsCsv = Join-Path $ReportDir "Findings.csv"
$findingsJson = Join-Path $ReportDir "Findings.json"
$Script:Findings | Export-Csv -Path $findingsCsv -NoTypeInformation -Encoding UTF8
$Script:Findings | ConvertTo-Json -Depth 5 | Out-File -FilePath $findingsJson -Encoding UTF8 -Width 4096

$failCount = @($Script:Findings | Where-Object { $_.Status -eq "FAIL" }).Count
$warnCount = @($Script:Findings | Where-Object { $_.Status -eq "WARN" }).Count
$passCount = @($Script:Findings | Where-Object { $_.Status -eq "PASS" }).Count

$overall = "Looks OK from automated checks"
$overallClass = "pass"
$overallAdvice = "Still complete the manual checklist before paying."
if ($failCount -gt 0) {
    $overall = "Do not buy until FAIL items are understood"
    $overallClass = "fail"
    $overallAdvice = "FAIL items are serious. Walk away or price in a confirmed repair."
} elseif ($warnCount -ge 6) {
    $overall = "Investigate before buying"
    $overallClass = "warn"
    $overallAdvice = "Several warnings were found. Use them for negotiation or ask for more testing time."
} elseif ($warnCount -gt 0) {
    $overall = "Mostly OK, with warnings"
    $overallClass = "warn"
    $overallAdvice = "Warnings may be normal for a used laptop, but inspect them before paying."
}

$rowsHtml = foreach ($f in $Script:Findings) {
    '<tr class="{0}"><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td><td>{6}</td></tr>' -f `
        (HtmlEncode $f.Status).ToLower(), (HtmlEncode $f.Status), (HtmlEncode $f.Category), (HtmlEncode $f.Item), (HtmlEncode $f.Value), (HtmlEncode $f.Detail), (HtmlEncode $f.Action)
}

$html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Used PC Checker Summary</title>
<style>
body { margin: 0; font-family: Segoe UI, Arial, sans-serif; color: #17202a; background: #f4f6f8; }
header { padding: 22px 28px; background: #17202a; color: #fff; }
h1 { margin: 0 0 6px; font-size: 26px; }
.sub { color: #cbd5df; }
main { padding: 20px 28px 32px; }
.summary { display: grid; grid-template-columns: 1.5fr repeat(3, minmax(100px, .3fr)); gap: 12px; margin-bottom: 16px; }
.card { background: #fff; border: 1px solid #d9e1e8; border-radius: 8px; padding: 14px; }
.decision.pass { border-left: 8px solid #1f9d68; }
.decision.warn { border-left: 8px solid #d39b16; }
.decision.fail { border-left: 8px solid #d64545; }
.metric b { display: block; font-size: 28px; }
.metric span { color: #52606d; }
table { width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #d9e1e8; }
th, td { text-align: left; vertical-align: top; border-bottom: 1px solid #e6ebef; padding: 9px 10px; font-size: 13px; }
th { position: sticky; top: 0; background: #eef2f6; z-index: 1; }
tr.fail td:first-child { color: #b42318; font-weight: 700; }
tr.warn td:first-child { color: #9a6700; font-weight: 700; }
tr.pass td:first-child { color: #157347; font-weight: 700; }
tr.info td:first-child { color: #1f5f99; font-weight: 700; }
tr.error td:first-child { color: #9b1c7c; font-weight: 700; }
.files { margin: 14px 0; color: #52606d; }
.files code { color: #17202a; }
@media (max-width: 900px) { .summary { grid-template-columns: 1fr; } th, td { font-size: 12px; } }
</style>
</head>
<body>
<header>
<h1>Used PC Checker Summary</h1>
<div class="sub">$([System.Net.WebUtility]::HtmlEncode($env:COMPUTERNAME)) - $(Get-Date)</div>
</header>
<main>
<div class="summary">
<div class="card decision $overallClass">
<h2>$([System.Net.WebUtility]::HtmlEncode($overall))</h2>
<p>$([System.Net.WebUtility]::HtmlEncode($overallAdvice))</p>
</div>
<div class="card metric"><b>$failCount</b><span>FAIL</span></div>
<div class="card metric"><b>$warnCount</b><span>WARN</span></div>
<div class="card metric"><b>$passCount</b><span>PASS</span></div>
</div>
<div class="files">
Report folder: <code>$([System.Net.WebUtility]::HtmlEncode($ReportDir))</code><br>
Raw data is in the <code>raw</code> folder. Battery report is saved as <code>BatteryReport.html</code> when available. CrystalDiskInfo output is saved as <code>raw\crystaldiskinfo_report.txt</code> when available.
</div>
<table>
<thead><tr><th>Status</th><th>Category</th><th>Item</th><th>Value</th><th>Detail</th><th>Action</th></tr></thead>
<tbody>
$($rowsHtml -join "`n")
</tbody>
</table>
</main>
</body>
</html>
"@

$summaryPath = Join-Path $ReportDir "Summary.html"
$html | Out-File -FilePath $summaryPath -Encoding UTF8 -Width 4096

try { Stop-Transcript | Out-Null } catch {}

Write-Host ""
Write-Host "Done." -ForegroundColor Green
Write-Host ("Summary report: {0}" -f $summaryPath) -ForegroundColor White
Write-Host ("Findings CSV:   {0}" -f $findingsCsv)
Write-Host ""
Write-Host "Open Summary.html and check FAIL/WARN rows before buying." -ForegroundColor Yellow

if (-not $NoOpen) {
    try { Start-Process $summaryPath } catch {}
}

if (($Host.Name -match "ConsoleHost") -and -not $NoPause) {
    Write-Host ""
    Read-Host "Press Enter to return to the USB menu"
}
