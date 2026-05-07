[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$ScriptDir = Split-Path -Parent $PSCommandPath
$KitDir = Split-Path -Parent $ScriptDir
$UsbRoot = Split-Path -Parent $KitDir
$ReportsRoot = Join-Path $UsbRoot 'Reports'
New-Item -ItemType Directory -Force -Path $ReportsRoot | Out-Null

function HtmlEncode {
    param([object]$Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Get-SafeRows {
    param([scriptblock]$Block)
    try {
        $rows = @(& $Block | Where-Object { $null -ne $_ })
        return $rows
    } catch {
        return @()
    }
}

function Format-ListBlock {
    param(
        [string]$Title,
        [object[]]$Rows,
        [string[]]$Properties
    )

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add($Title)
    $lines.Add(('-' * $Title.Length))
    if (-not $Rows -or $Rows.Count -eq 0) {
        $lines.Add('None detected.')
        $lines.Add('')
        return ($lines -join [Environment]::NewLine)
    }

    $index = 1
    foreach ($row in $Rows) {
        $parts = foreach ($prop in $Properties) {
            $value = $row.$prop
            if ($null -ne $value -and [string]$value -ne '') {
                '{0}: {1}' -f $prop, $value
            }
        }
        $lines.Add(('{0}. {1}' -f $index, ($parts -join ' | ')))
        $index++
    }
    $lines.Add('')
    return ($lines -join [Environment]::NewLine)
}

function Get-HardwareSnapshot {
    $pnpAvailable = [bool](Get-Command Get-PnpDevice -ErrorAction SilentlyContinue)
    $pnp = @()
    if ($pnpAvailable) {
        $pnp = Get-SafeRows { Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue }
    }

    $usb = @()
    $cameras = @()
    $media = @()
    $displays = @()
    if ($pnpAvailable) {
        $usb = @($pnp | Where-Object { $_.Class -eq 'USB' -or $_.InstanceId -match '^USB\\|^USBSTOR\\' } |
            Select-Object Status, Class, FriendlyName, InstanceId)
        $cameras = @($pnp | Where-Object { $_.Class -in @('Camera','Image') } |
            Select-Object Status, Class, FriendlyName, InstanceId)
        $media = @($pnp | Where-Object { $_.Class -eq 'Media' } |
            Select-Object Status, Class, FriendlyName, InstanceId)
        $displays = @($pnp | Where-Object { $_.Class -in @('Monitor','Display') } |
            Select-Object Status, Class, FriendlyName, InstanceId)
    }

    $removable = Get-SafeRows {
        Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=2' -ErrorAction SilentlyContinue |
            Select-Object DeviceID, VolumeName, FileSystem, Size, FreeSpace
    }

    $net = @()
    if (Get-Command Get-NetAdapter -ErrorAction SilentlyContinue) {
        $net = Get-SafeRows {
            Get-NetAdapter -ErrorAction SilentlyContinue |
                Select-Object Name, InterfaceDescription, Status, LinkSpeed, MacAddress
        }
    } else {
        $net = Get-SafeRows {
            Get-CimInstance Win32_NetworkAdapter -Filter 'PhysicalAdapter=True' -ErrorAction SilentlyContinue |
                Select-Object Name, NetConnectionStatus, Speed, MACAddress
        }
    }

    $battery = Get-SafeRows {
        Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue |
            Select-Object DeviceID, BatteryStatus, EstimatedChargeRemaining
    }

    $sound = Get-SafeRows {
        Get-CimInstance Win32_SoundDevice -ErrorAction SilentlyContinue |
            Select-Object Name, Manufacturer, Status
    }

    return [pscustomobject]@{
        Time = Get-Date
        UsbDevices = $usb
        RemovableDrives = $removable
        Displays = $displays
        NetworkAdapters = $net
        AudioDevices = $sound
        Cameras = $cameras
        MediaDevices = $media
        Batteries = $battery
    }
}

function Convert-SnapshotToText {
    param([object]$Snapshot)

    $sections = @(
        "Snapshot time: $($Snapshot.Time)",
        '',
        (Format-ListBlock 'USB devices' $Snapshot.UsbDevices @('Status','Class','FriendlyName')),
        (Format-ListBlock 'Removable drives / USB storage' $Snapshot.RemovableDrives @('DeviceID','VolumeName','FileSystem','Size','FreeSpace')),
        (Format-ListBlock 'Displays / display outputs' $Snapshot.Displays @('Status','Class','FriendlyName')),
        (Format-ListBlock 'Network adapters' $Snapshot.NetworkAdapters @('Name','InterfaceDescription','Status','LinkSpeed','MacAddress')),
        (Format-ListBlock 'Audio devices' $Snapshot.AudioDevices @('Name','Manufacturer','Status')),
        (Format-ListBlock 'Camera / image devices' $Snapshot.Cameras @('Status','Class','FriendlyName')),
        (Format-ListBlock 'Media devices' $Snapshot.MediaDevices @('Status','Class','FriendlyName')),
        (Format-ListBlock 'Battery / charging status' $Snapshot.Batteries @('DeviceID','BatteryStatus','EstimatedChargeRemaining'))
    )
    return ($sections -join [Environment]::NewLine)
}

function Get-PortRowsFromGrid {
    param([System.Windows.Forms.DataGridView]$Grid)

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($gridRow in $Grid.Rows) {
        if ($gridRow.IsNewRow) { continue }
        $port = [string]$gridRow.Cells['Port'].Value
        if ([string]::IsNullOrWhiteSpace($port)) { continue }
        $status = [string]$gridRow.Cells['Status'].Value
        if ([string]::IsNullOrWhiteSpace($status)) { $status = 'Untested' }
        $notes = [string]$gridRow.Cells['Notes'].Value
        $rows.Add([pscustomobject]@{
            Port = $port
            Status = $status
            Notes = $notes
        })
    }
    return @($rows)
}

function Save-PortReport {
    param(
        [System.Windows.Forms.DataGridView]$Grid,
        [object]$Snapshot,
        [string]$SnapshotText
    )

    $safeComputer = ($env:COMPUTERNAME -replace '[^a-zA-Z0-9_-]', '_')
    $stamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
    $reportDir = Join-Path $ReportsRoot "$stamp-$safeComputer-PortCheck"
    New-Item -ItemType Directory -Force -Path $reportDir | Out-Null

    $rows = Get-PortRowsFromGrid -Grid $Grid
    $csvPath = Join-Path $reportDir 'Port_Checker_Findings.csv'
    $rows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

    $snapshotPath = Join-Path $reportDir 'Hardware_Snapshot.txt'
    $SnapshotText | Out-File -FilePath $snapshotPath -Encoding UTF8 -Width 4096

    $passCount = @($rows | Where-Object { $_.Status -eq 'PASS' }).Count
    $failCount = @($rows | Where-Object { $_.Status -eq 'FAIL' }).Count
    $untestedCount = @($rows | Where-Object { $_.Status -eq 'Untested' }).Count
    $naCount = @($rows | Where-Object { $_.Status -eq 'N/A' }).Count

    $rowHtml = foreach ($row in $rows) {
        '<tr class="{0}"><td>{1}</td><td>{2}</td><td>{3}</td></tr>' -f `
            (HtmlEncode $row.Status).ToLower(), (HtmlEncode $row.Port), (HtmlEncode $row.Status), (HtmlEncode $row.Notes)
    }

    $html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Port Checker Report</title>
<style>
body { margin: 0; font-family: Segoe UI, Arial, sans-serif; color: #18212b; background: #eef2f4; }
header { padding: 18px 22px; background: #18212b; color: #fff; }
h1 { margin: 0 0 5px; font-size: 24px; }
main { padding: 18px 22px 28px; }
.stats { display: grid; grid-template-columns: repeat(4, minmax(120px, 1fr)); gap: 10px; margin-bottom: 14px; }
.stat, .panel { background: #fff; border: 1px solid #cfd8df; border-radius: 8px; padding: 12px; }
.stat b { display: block; font-size: 26px; color: #2563a8; }
table { width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #cfd8df; }
th, td { border-bottom: 1px solid #e2e8ed; text-align: left; vertical-align: top; padding: 9px 10px; font-size: 13px; }
th { background: #f4f7f9; }
tr.pass td:nth-child(2) { color: #0f684d; font-weight: 700; }
tr.fail td:nth-child(2) { color: #9e2f27; font-weight: 700; }
pre { white-space: pre-wrap; word-break: break-word; background: #fff; border: 1px solid #cfd8df; border-radius: 8px; padding: 12px; }
@media (max-width: 760px) { .stats { grid-template-columns: 1fr 1fr; } }
</style>
</head>
<body>
<header>
<h1>Port Checker Report</h1>
<div>$([System.Net.WebUtility]::HtmlEncode($env:COMPUTERNAME)) - $(Get-Date)</div>
</header>
<main>
<div class="stats">
<div class="stat"><b>$passCount</b><span>PASS</span></div>
<div class="stat"><b>$failCount</b><span>FAIL</span></div>
<div class="stat"><b>$untestedCount</b><span>Untested</span></div>
<div class="stat"><b>$naCount</b><span>N/A</span></div>
</div>
<table>
<thead><tr><th>Port</th><th>Status</th><th>Notes</th></tr></thead>
<tbody>
$($rowHtml -join "`n")
</tbody>
</table>
<h2>Live Hardware Snapshot</h2>
<pre>$([System.Net.WebUtility]::HtmlEncode($SnapshotText))</pre>
</main>
</body>
</html>
"@

    $htmlPath = Join-Path $reportDir 'Port_Checker_Report.html'
    $html | Out-File -FilePath $htmlPath -Encoding UTF8 -Width 4096
    return $htmlPath
}

[System.Windows.Forms.Application]::EnableVisualStyles()

$form = New-Object System.Windows.Forms.Form
$form.Text = 'Used PC Port Checker'
$form.StartPosition = 'CenterScreen'
$form.MinimumSize = New-Object System.Drawing.Size(980, 680)
$form.Size = New-Object System.Drawing.Size(1120, 760)
$form.BackColor = [System.Drawing.Color]::FromArgb(238, 242, 244)

$topPanel = New-Object System.Windows.Forms.Panel
$topPanel.Dock = 'Top'
$topPanel.Height = 84
$topPanel.Padding = New-Object System.Windows.Forms.Padding(12)
$topPanel.BackColor = [System.Drawing.Color]::White
$form.Controls.Add($topPanel)

$title = New-Object System.Windows.Forms.Label
$title.Text = 'Port Checker'
$title.Font = New-Object System.Drawing.Font('Segoe UI', 15, [System.Drawing.FontStyle]::Bold)
$title.AutoSize = $true
$title.Location = New-Object System.Drawing.Point(12, 10)
$topPanel.Controls.Add($title)

$subtitle = New-Object System.Windows.Forms.Label
$subtitle.Text = 'Plug a device into each port, click Refresh Hardware, then mark PASS, FAIL, N/A, or leave Untested.'
$subtitle.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$subtitle.ForeColor = [System.Drawing.Color]::FromArgb(82, 96, 109)
$subtitle.AutoSize = $true
$subtitle.Location = New-Object System.Drawing.Point(14, 42)
$topPanel.Controls.Add($subtitle)

$btnRefresh = New-Object System.Windows.Forms.Button
$btnRefresh.Text = 'Refresh Hardware'
$btnRefresh.Size = New-Object System.Drawing.Size(130, 32)
$btnRefresh.Anchor = 'Top,Right'
$btnRefresh.Location = New-Object System.Drawing.Point(640, 24)
$topPanel.Controls.Add($btnRefresh)

$btnAdd = New-Object System.Windows.Forms.Button
$btnAdd.Text = 'Add Port'
$btnAdd.Size = New-Object System.Drawing.Size(90, 32)
$btnAdd.Anchor = 'Top,Right'
$btnAdd.Location = New-Object System.Drawing.Point(780, 24)
$topPanel.Controls.Add($btnAdd)

$btnSave = New-Object System.Windows.Forms.Button
$btnSave.Text = 'Save HTML Report'
$btnSave.Size = New-Object System.Drawing.Size(130, 32)
$btnSave.Anchor = 'Top,Right'
$btnSave.Location = New-Object System.Drawing.Point(880, 24)
$topPanel.Controls.Add($btnSave)

$btnReports = New-Object System.Windows.Forms.Button
$btnReports.Text = 'Reports'
$btnReports.Size = New-Object System.Drawing.Size(80, 32)
$btnReports.Anchor = 'Top,Right'
$btnReports.Location = New-Object System.Drawing.Point(1020, 24)
$topPanel.Controls.Add($btnReports)

$split = New-Object System.Windows.Forms.SplitContainer
$split.Dock = 'Fill'
$split.Orientation = 'Vertical'
$split.SplitterDistance = 565
$split.Panel1.Padding = New-Object System.Windows.Forms.Padding(12)
$split.Panel2.Padding = New-Object System.Windows.Forms.Padding(0, 12, 12, 12)
$form.Controls.Add($split)

$grid = New-Object System.Windows.Forms.DataGridView
$grid.Dock = 'Fill'
$grid.AllowUserToAddRows = $false
$grid.AllowUserToDeleteRows = $true
$grid.AutoSizeColumnsMode = 'Fill'
$grid.BackgroundColor = [System.Drawing.Color]::White
$grid.BorderStyle = 'FixedSingle'
$grid.RowHeadersVisible = $false
$grid.SelectionMode = 'FullRowSelect'
$grid.MultiSelect = $false
$grid.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$split.Panel1.Controls.Add($grid)

$portColumn = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$portColumn.Name = 'Port'
$portColumn.HeaderText = 'Port'
$portColumn.FillWeight = 38
$grid.Columns.Add($portColumn) | Out-Null

$statusColumn = New-Object System.Windows.Forms.DataGridViewComboBoxColumn
$statusColumn.Name = 'Status'
$statusColumn.HeaderText = 'Status'
$statusColumn.FillWeight = 20
$statusColumn.Items.AddRange(@('Untested', 'PASS', 'FAIL', 'N/A'))
$grid.Columns.Add($statusColumn) | Out-Null

$notesColumn = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$notesColumn.Name = 'Notes'
$notesColumn.HeaderText = 'Notes'
$notesColumn.FillWeight = 42
$grid.Columns.Add($notesColumn) | Out-Null

$defaultPorts = @(
    'Charger / charging port',
    'USB-A port 1',
    'USB-A port 2',
    'USB-A port 3',
    'USB-A port 4',
    'USB-C port 1',
    'USB-C port 2',
    'Thunderbolt / USB4',
    'HDMI output',
    'DisplayPort / mini DisplayPort',
    'Ethernet / RJ45',
    'Headphone jack',
    'Microphone jack',
    'SD / microSD card reader',
    'Webcam privacy switch',
    'Bluetooth pairing',
    'Wi-Fi connection'
)

foreach ($port in $defaultPorts) {
    $index = $grid.Rows.Add()
    $grid.Rows[$index].Cells['Port'].Value = $port
    $grid.Rows[$index].Cells['Status'].Value = 'Untested'
}

$rightPanel = New-Object System.Windows.Forms.TableLayoutPanel
$rightPanel.Dock = 'Fill'
$rightPanel.RowCount = 3
$rightPanel.ColumnCount = 1
$rightPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 34))) | Out-Null
$rightPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
$rightPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 30))) | Out-Null
$split.Panel2.Controls.Add($rightPanel)

$snapshotTitle = New-Object System.Windows.Forms.Label
$snapshotTitle.Text = 'Live hardware snapshot'
$snapshotTitle.Dock = 'Fill'
$snapshotTitle.Font = New-Object System.Drawing.Font('Segoe UI', 11, [System.Drawing.FontStyle]::Bold)
$snapshotTitle.TextAlign = 'MiddleLeft'
$rightPanel.Controls.Add($snapshotTitle, 0, 0)

$snapshotBox = New-Object System.Windows.Forms.TextBox
$snapshotBox.Dock = 'Fill'
$snapshotBox.Multiline = $true
$snapshotBox.ReadOnly = $true
$snapshotBox.ScrollBars = 'Both'
$snapshotBox.WordWrap = $false
$snapshotBox.Font = New-Object System.Drawing.Font('Consolas', 9)
$snapshotBox.BackColor = [System.Drawing.Color]::White
$rightPanel.Controls.Add($snapshotBox, 0, 1)

$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Dock = 'Fill'
$statusLabel.TextAlign = 'MiddleLeft'
$statusLabel.ForeColor = [System.Drawing.Color]::FromArgb(82, 96, 109)
$rightPanel.Controls.Add($statusLabel, 0, 2)

$currentSnapshot = $null
$currentSnapshotText = ''

function Refresh-Snapshot {
    $script:currentSnapshot = Get-HardwareSnapshot
    $script:currentSnapshotText = Convert-SnapshotToText -Snapshot $script:currentSnapshot
    $snapshotBox.Text = $script:currentSnapshotText
    $statusLabel.Text = 'Last refresh: ' + (Get-Date).ToString('HH:mm:ss')
}

$btnRefresh.Add_Click({ Refresh-Snapshot })
$btnAdd.Add_Click({
    $index = $grid.Rows.Add()
    $grid.Rows[$index].Cells['Port'].Value = 'Custom port'
    $grid.Rows[$index].Cells['Status'].Value = 'Untested'
    $grid.CurrentCell = $grid.Rows[$index].Cells['Port']
    $grid.BeginEdit($true)
})
$btnReports.Add_Click({
    if (-not (Test-Path $ReportsRoot)) { New-Item -ItemType Directory -Force -Path $ReportsRoot | Out-Null }
    Start-Process $ReportsRoot
})
$btnSave.Add_Click({
    if (-not $script:currentSnapshot) { Refresh-Snapshot }
    $path = Save-PortReport -Grid $grid -Snapshot $script:currentSnapshot -SnapshotText $script:currentSnapshotText
    $statusLabel.Text = 'Saved: ' + $path
    Start-Process $path
})

$form.Add_Shown({ Refresh-Snapshot })
[void]$form.ShowDialog()
