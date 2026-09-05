<#
.SYNOPSIS
    Auto-fills the "easy" checks in a Cisco IOS Switch NDM .cklb using a
    device running-config, and saves a new .cklb with the results.

.DESCRIPTION
    Double-click friendly: right-click this file -> "Run with PowerShell".
    If you don't pass -CklbPath / -ConfigPath / -OutputPath on the command
    line, it will pop up file-picker dialogs instead.

    Covers 14 rules from the Cisco IOS Switch NDM STIG (matched by the
    stable "rule_version" / STIG ID field, e.g. CISC-ND-000550, so it keeps
    working even if Cisco/DISA bump the SV-xxxxxx revision number later):

      CISC-ND-000010  Concurrent session limit (vty/http)
      CISC-ND-000160  Login banner present
      CISC-ND-000470  Unnecessary services disabled
      CISC-ND-000490  Single local account (heuristic - verify manually)
      CISC-ND-000550  Password min-length >= 15
      CISC-ND-000570  Password upper-case >= 1
      CISC-ND-000580  Password lower-case >= 1
      CISC-ND-000590  Password numeric-count >= 1
      CISC-ND-000600  Password special-case >= 1
      CISC-ND-000610  Password char-changes >= 8
      CISC-ND-000620  Passwords encrypted (service password-encryption / enable secret)
      CISC-ND-000720  exec-timeout <= 5 min on con/vty lines
      CISC-ND-001030  NTP server(s) configured
      CISC-ND-001150  NTP authentication configured

    Every other rule in the cklb (audit logging, AAA server, cert auth,
    IOS version support, etc.) is intentionally left "not_reviewed" because
    those genuinely need a human to check logs, external servers, or the
    Cisco support matrix - trying to regex those reliably would just create
    false confidence.

    ALWAYS spot-check the auto-filled results against the actual config
    before you submit the cklb. This is a time-saver, not a substitute for
    review.

.PARAMETER CklbPath
    Path to the input .cklb file. If omitted, a file picker opens.

.PARAMETER ConfigPath
    Path to the plain-text device config ("show running-config" output).
    If omitted, a file picker opens.

.PARAMETER OutputPath
    Path to write the updated .cklb. If omitted, a save-file dialog opens,
    defaulting to "<original name>_filled.cklb" next to the input file.
#>

<#
.SYNOPSIS
    Auto-fills the "easy" checks in a Cisco IOS Switch NDM .cklb for one or
    many devices at once, using one blank/template cklb plus each device's
    running-config, and saves a separate filled .cklb per device.

.DESCRIPTION
    Double-click friendly: right-click this file -> "Run with PowerShell".
    If you don't pass parameters, it prompts with file/folder dialogs:
      1. Pick ONE template .cklb (used as the starting point for every device)
      2. Pick ONE OR MORE device config text files (multi-select in the dialog)
      3. Pick an output folder - one "<name>_filled.cklb" is written per device

    Each output file is named after the device's "hostname" line in its
    config if one is found, otherwise after the config file's own name.

    Covers 14 rules from the Cisco IOS Switch NDM STIG (matched by the
    stable "rule_version" / STIG ID field, e.g. CISC-ND-000550, so it keeps
    working even if Cisco/DISA bump the SV-xxxxxx revision number later):

      CISC-ND-000010  Concurrent session limit (vty/http)
      CISC-ND-000160  Login banner present
      CISC-ND-000470  Unnecessary services disabled
      CISC-ND-000490  Single local account (heuristic - verify manually)
      CISC-ND-000550  Password min-length >= 15
      CISC-ND-000570  Password upper-case >= 1
      CISC-ND-000580  Password lower-case >= 1
      CISC-ND-000590  Password numeric-count >= 1
      CISC-ND-000600  Password special-case >= 1
      CISC-ND-000610  Password char-changes >= 8
      CISC-ND-000620  Passwords encrypted (service password-encryption / enable secret)
      CISC-ND-000720  exec-timeout <= 5 min on con/vty lines
      CISC-ND-001030  NTP server(s) configured
      CISC-ND-001150  NTP authentication configured

    Every other rule in the cklb (audit logging, AAA server, cert auth,
    IOS version support, etc.) is intentionally left "not_reviewed" because
    those genuinely need a human to check logs, external servers, or the
    Cisco support matrix - trying to regex those reliably would just create
    false confidence.

    ALWAYS spot-check the auto-filled results against the actual config
    before you submit each cklb. This is a time-saver, not a substitute for
    review.

.PARAMETER CklbTemplatePath
    Path to the template .cklb file used as the starting point for every
    device. If omitted, a file picker opens.

.PARAMETER ConfigPaths
    One or more paths to plain-text device configs ("show running-config"
    output). If omitted, a multi-select file picker opens. Can also be a
    single folder path, in which case every .txt/.cfg/.log file in it is used.

.PARAMETER OutputFolder
    Folder to write the filled .cklb files into (one per config). If
    omitted, a folder picker opens.
#>

[CmdletBinding()]
param(
    [string]$CklbTemplatePath,
    [string[]]$ConfigPaths,
    [string]$OutputFolder
)

$ErrorActionPreference = "Stop"

function Pause-Exit {
    param([int]$Code = 0)
    Write-Host ""
    Read-Host "Press Enter to close"
    exit $Code
}

# ---------------------------------------------------------------------------
# 0. GUI pickers (so this can be run by double-click / right-click)
# ---------------------------------------------------------------------------

Add-Type -AssemblyName System.Windows.Forms | Out-Null

if (-not $CklbTemplatePath) {
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Title  = "Select the template .cklb file"
    $dlg.Filter = "CKLB files (*.cklb)|*.cklb|All files (*.*)|*.*"
    if ($dlg.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
        Write-Host "No cklb file selected. Exiting."
        Pause-Exit 1
    }
    $CklbTemplatePath = $dlg.FileName
}

if (-not $ConfigPaths -or $ConfigPaths.Count -eq 0) {
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Title       = "Select one or more device config files"
    $dlg.Filter      = "Text files (*.txt,*.cfg,*.log)|*.txt;*.cfg;*.log|All files (*.*)|*.*"
    $dlg.Multiselect = $true
    if ($dlg.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
        Write-Host "No config file(s) selected. Exiting."
        Pause-Exit 1
    }
    $ConfigPaths = $dlg.FileNames
} elseif ($ConfigPaths.Count -eq 1 -and (Test-Path $ConfigPaths[0] -PathType Container)) {
    # A single folder was passed - expand it to every config file inside.
    $ConfigPaths = Get-ChildItem -Path $ConfigPaths[0] -Include *.txt, *.cfg, *.log -File -Recurse | Select-Object -ExpandProperty FullName
}

if (-not $OutputFolder) {
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    $dlg.Description = "Select a folder to save the filled cklb files into"
    if ($dlg.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
        Write-Host "No output folder chosen. Exiting."
        Pause-Exit 1
    }
    $OutputFolder = $dlg.SelectedPath
}

if (-not (Test-Path $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder | Out-Null
}

Write-Host "Template cklb: $CklbTemplatePath"
Write-Host "Devices to process: $($ConfigPaths.Count)"
Write-Host "Output folder: $OutputFolder"
Write-Host ""

$cklbTemplateText = Get-Content -Raw -Path $CklbTemplatePath -Encoding UTF8

# ---------------------------------------------------------------------------
# 1. Helpers
# ---------------------------------------------------------------------------

function Get-CcPolicyBlock {
    # Pulls the body of the first "aaa common-criteria policy <name>" block
    # out of the config (Cisco prints its settings as indented lines below
    # the policy name, terminated by a bare "!").
    param([string]$Config)
    $m = [regex]::Match($Config, '(?ms)^aaa common-criteria policy\s+\S+\s*\r?\n(.*?)(?=^!)')
    if ($m.Success) { return $m.Groups[1].Value }
    return $null
}

function Get-DeviceName {
    # Names the output file after the device's "hostname" line if present,
    # otherwise falls back to the config file's own base name.
    param([string]$Config, [string]$FallbackName)
    $m = [regex]::Match($Config, '(?im)^hostname\s+(\S+)')
    if ($m.Success) { return $m.Groups[1].Value }
    return $FallbackName
}

# ---------------------------------------------------------------------------
# 2. Rule checks, keyed by the cklb's stable "rule_version" (STIG ID) field
# ---------------------------------------------------------------------------

$RuleChecks = @{

    "CISC-ND-000010" = {
        param($cfg)
        $sessionLimit = [regex]::IsMatch($cfg, '(?im)^\s*session-limit\s+\d+')
        $vtyRestricted = [regex]::IsMatch($cfg, '(?im)^\s*transport input\s+none')
        $httpLimited  = [regex]::IsMatch($cfg, '(?im)^ip http max-connections\s+\d+')
        if ($sessionLimit -or $vtyRestricted -or $httpLimited) {
            return @{ Match = $true; Detail = "Found session-limit / restricted vty transport / ip http max-connections in config. Verify the actual number matches your org's approved limit." }
        }
        return @{ Match = $false; Detail = "No session-limit, restricted 'transport input none' vty line, or 'ip http max-connections' found." }
    }

    "CISC-ND-000160" = {
        param($cfg)
        if ($cfg -match '(?im)^banner login') {
            return @{ Match = $true; Detail = "'banner login' block is configured. Manually verify the banner text matches the required DoD notice-and-consent wording." }
        }
        return @{ Match = $false; Detail = "No 'banner login' statement found in configuration." }
    }

    "CISC-ND-000470" = {
        param($cfg)
        $badServices = @(
            'boot network', 'ip boot server', 'ip bootp server', 'ip dns server',
            'ip identd', 'ip finger', 'ip http server', 'ip rcmd rcp-enable',
            'ip rcmd rsh-enable', 'service config', 'service finger',
            'service tcp-small-servers', 'service udp-small-servers'
        )
        $found = @()
        foreach ($svc in $badServices) {
            if ([regex]::IsMatch($cfg, "(?im)^\s*$([regex]::Escape($svc))\s*$")) {
                $found += $svc
            }
        }
        if ($found.Count -eq 0) {
            return @{ Match = $true; Detail = "None of the unnecessary/non-secure services checked were found enabled." }
        }
        return @{ Match = $false; Detail = "Unnecessary service(s) still enabled: $($found -join ', ')" }
    }

    "CISC-ND-000490" = {
        param($cfg)
        $userLines = [regex]::Matches($cfg, '(?im)^username\s+(\S+)')
        $names = $userLines | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique
        if ($names.Count -eq 1) {
            return @{ Match = $true; Detail = "Exactly one local account configured: $($names[0]). Manually confirm it is documented as the account-of-last-resort." }
        }
        return @{ Match = $false; Detail = "Found $($names.Count) local account(s): $($names -join ', '). Manual review required - multiple accounts may be justified but must be documented." }
    }

    "CISC-ND-000550" = {
        param($cfg, $ccBlock)
        if (-not $ccBlock) { return @{ Match = $false; Detail = "No 'aaa common-criteria policy' block found in configuration." } }
        $m = [regex]::Match($ccBlock, '(?im)^\s*min-length\s+(\d+)')
        if ($m.Success) {
            $len = [int]$m.Groups[1].Value
            if ($len -ge 15) { return @{ Match = $true; Detail = "Common-criteria policy min-length is $len (>= 15)." } }
            return @{ Match = $false; Detail = "Common-criteria policy min-length is $len (< 15 required)." }
        }
        return @{ Match = $false; Detail = "No 'min-length' setting found in the common-criteria policy block." }
    }

    "CISC-ND-000570" = {
        param($cfg, $ccBlock)
        if (-not $ccBlock) { return @{ Match = $false; Detail = "No 'aaa common-criteria policy' block found in configuration." } }
        $m = [regex]::Match($ccBlock, '(?im)^\s*upper-case\s+(\d+)')
        if ($m.Success -and [int]$m.Groups[1].Value -ge 1) {
            return @{ Match = $true; Detail = "Common-criteria policy requires upper-case $($m.Groups[1].Value) character(s)." }
        }
        return @{ Match = $false; Detail = "No 'upper-case' requirement (>=1) found in the common-criteria policy block." }
    }

    "CISC-ND-000580" = {
        param($cfg, $ccBlock)
        if (-not $ccBlock) { return @{ Match = $false; Detail = "No 'aaa common-criteria policy' block found in configuration." } }
        $m = [regex]::Match($ccBlock, '(?im)^\s*lower-case\s+(\d+)')
        if ($m.Success -and [int]$m.Groups[1].Value -ge 1) {
            return @{ Match = $true; Detail = "Common-criteria policy requires lower-case $($m.Groups[1].Value) character(s)." }
        }
        return @{ Match = $false; Detail = "No 'lower-case' requirement (>=1) found in the common-criteria policy block." }
    }

    "CISC-ND-000590" = {
        param($cfg, $ccBlock)
        if (-not $ccBlock) { return @{ Match = $false; Detail = "No 'aaa common-criteria policy' block found in configuration." } }
        $m = [regex]::Match($ccBlock, '(?im)^\s*numeric-count\s+(\d+)')
        if ($m.Success -and [int]$m.Groups[1].Value -ge 1) {
            return @{ Match = $true; Detail = "Common-criteria policy requires numeric-count $($m.Groups[1].Value) character(s)." }
        }
        return @{ Match = $false; Detail = "No 'numeric-count' requirement (>=1) found in the common-criteria policy block." }
    }

    "CISC-ND-000600" = {
        param($cfg, $ccBlock)
        if (-not $ccBlock) { return @{ Match = $false; Detail = "No 'aaa common-criteria policy' block found in configuration." } }
        $m = [regex]::Match($ccBlock, '(?im)^\s*special-case\s+(\d+)')
        if ($m.Success -and [int]$m.Groups[1].Value -ge 1) {
            return @{ Match = $true; Detail = "Common-criteria policy requires special-case $($m.Groups[1].Value) character(s)." }
        }
        return @{ Match = $false; Detail = "No 'special-case' requirement (>=1) found in the common-criteria policy block." }
    }

    "CISC-ND-000610" = {
        param($cfg, $ccBlock)
        if (-not $ccBlock) { return @{ Match = $false; Detail = "No 'aaa common-criteria policy' block found in configuration." } }
        $m = [regex]::Match($ccBlock, '(?im)^\s*char-changes\s+(\d+)')
        if ($m.Success) {
            $val = [int]$m.Groups[1].Value
            if ($val -ge 8) { return @{ Match = $true; Detail = "Common-criteria policy char-changes is $val (>= 8)." } }
            return @{ Match = $false; Detail = "Common-criteria policy char-changes is $val (< 8 required)." }
        }
        return @{ Match = $false; Detail = "No 'char-changes' setting found in the common-criteria policy block." }
    }

    "CISC-ND-000620" = {
        param($cfg)
        $encSvc = [regex]::IsMatch($cfg, '(?im)^service password-encryption')
        $encSecret = [regex]::IsMatch($cfg, '(?im)^enable secret')
        $weakEnable = [regex]::IsMatch($cfg, '(?im)^enable password(?!\s+secret)')
        if ($encSvc -and $encSecret -and -not $weakEnable) {
            return @{ Match = $true; Detail = "'service password-encryption' and 'enable secret' are configured; no weak 'enable password' found." }
        }
        $missing = @()
        if (-not $encSvc) { $missing += "service password-encryption" }
        if (-not $encSecret) { $missing += "enable secret" }
        if ($weakEnable) { $missing += "weak 'enable password' is present" }
        return @{ Match = $false; Detail = "Password encryption issue(s): $($missing -join '; ')" }
    }

    "CISC-ND-000720" = {
        param($cfg)
        $timeouts = [regex]::Matches($cfg, '(?im)^\s*exec-timeout\s+(\d+)\s+(\d+)')
        if ($timeouts.Count -eq 0) {
            return @{ Match = $false; Detail = "No 'exec-timeout' statements found on any line." }
        }
        $tooLong = @()
        foreach ($t in $timeouts) {
            $min = [int]$t.Groups[1].Value
            $sec = [int]$t.Groups[2].Value
            if ($min -gt 5 -or ($min -eq 0 -and $sec -eq 0)) { $tooLong += "$min`:$sec" }
        }
        if ($tooLong.Count -eq 0) {
            return @{ Match = $true; Detail = "All $($timeouts.Count) exec-timeout statement(s) found are <= 5 minutes." }
        }
        return @{ Match = $false; Detail = "Found exec-timeout value(s) exceeding 5 minutes or disabled (0 0): $($tooLong -join ', '). Verify this applies to con/vty lines." }
    }

    "CISC-ND-001030" = {
        param($cfg)
        $servers = [regex]::Matches($cfg, '(?im)^ntp server\s+(\S+)') | ForEach-Object { $_.Groups[1].Value }
        if ($servers.Count -ge 2) {
            return @{ Match = $true; Detail = "NTP server(s) configured: $($servers -join ', ') (redundant sources present)." }
        } elseif ($servers.Count -eq 1) {
            return @{ Match = $false; Detail = "Only one NTP server configured ($($servers[0])); a redundant/secondary source is required." }
        }
        return @{ Match = $false; Detail = "No 'ntp server' statement found in configuration." }
    }

    "CISC-ND-001150" = {
        param($cfg)
        $authEnabled = [regex]::IsMatch($cfg, '(?im)^ntp authenticate')
        $hasKey      = [regex]::IsMatch($cfg, '(?im)^ntp authentication-key\s+\d+\s+(md5|sha1|sha2)')
        $trustedKey  = [regex]::IsMatch($cfg, '(?im)^ntp trusted-key\s+\d+')
        $serverKeyed = [regex]::IsMatch($cfg, '(?im)^ntp server\s+\S+\s+key\s+\d+')
        if ($authEnabled -and $hasKey -and $trustedKey -and $serverKeyed) {
            return @{ Match = $true; Detail = "NTP authentication is fully configured (ntp authenticate + authentication-key + trusted-key + keyed server line)." }
        }
        $missing = @()
        if (-not $authEnabled) { $missing += "ntp authenticate" }
        if (-not $hasKey) { $missing += "ntp authentication-key <id> md5/sha" }
        if (-not $trustedKey) { $missing += "ntp trusted-key" }
        if (-not $serverKeyed) { $missing += "ntp server ... key <id>" }
        return @{ Match = $false; Detail = "NTP authentication incomplete - missing: $($missing -join ', ')" }
    }
}

# ---------------------------------------------------------------------------
# 3. Process each device
# ---------------------------------------------------------------------------

$deviceSummaries = @()

foreach ($configPath in $ConfigPaths) {

    $configText    = Get-Content -Raw -Path $configPath -Encoding UTF8
    $ccPolicyBlock = Get-CcPolicyBlock -Config $configText
    $baseName      = [System.IO.Path]::GetFileNameWithoutExtension($configPath)
    $deviceName    = Get-DeviceName -Config $configText -FallbackName $baseName

    # Fresh parse of the template for every device - avoids any shared
    # object-reference state carrying over between iterations.
    $cklb = $cklbTemplateText | ConvertFrom-Json

    Write-Host "======================================================"
    Write-Host "Device: $deviceName  (config: $(Split-Path -Leaf $configPath))"
    Write-Host "======================================================"

    $appliedCount = 0
    $openCount    = 0
    $naFoundCount = 0
    $totalRules   = 0

    foreach ($stig in $cklb.stigs) {
        foreach ($rule in $stig.rules) {
            $totalRules++
            $key = $rule.rule_version

            if (-not $key -or -not $RuleChecks.ContainsKey($key)) { continue }

            try {
                $result = & $RuleChecks[$key] $configText $ccPolicyBlock
            } catch {
                Write-Warning "Check for $key ($($rule.rule_id)) threw an error: $_"
                continue
            }

            if ($null -eq $result) { continue }

            $rule.status          = if ($result.Match) { "not_a_finding" } else { "open" }
            $rule.finding_details = $result.Detail
            $rule.comments        = "Auto-filled by Fill-Cklb-CiscoNDM.ps1 on $(Get-Date -Format 'yyyy-MM-dd HH:mm') - verify before submitting."

            $appliedCount++
            if ($result.Match) { $naFoundCount++ } else { $openCount++ }

            $tag = if ($result.Match) { "NOT A FINDING" } else { "OPEN" }
            Write-Host "  [$($rule.group_id)] $tag - $($rule.rule_title.Substring(0, [Math]::Min(65, $rule.rule_title.Length)))"
        }
    }

    # Fresh checklist id per device output - avoids id collisions both
    # against the original template and against every other device's output.
    $oldId = $cklb.id
    $cklb.id = [guid]::NewGuid().ToString()

    $outputPath = Join-Path $OutputFolder "$deviceName`_filled.cklb"
    $jsonOut = $cklb | ConvertTo-Json -Depth 50
    # Windows PowerShell's -Encoding utf8 always prepends a UTF-8 BOM, which
    # breaks strict JSON parsers (like the checklist viewer). Write without BOM.
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($outputPath, $jsonOut, $utf8NoBom)

    Write-Host "  Checklist id: $oldId -> $($cklb.id)"
    Write-Host "  Saved: $outputPath"
    Write-Host ""

    $deviceSummaries += [PSCustomObject]@{
        Device      = $deviceName
        Total       = $totalRules
        Filled      = $appliedCount
        NotAFinding = $naFoundCount
        Open        = $openCount
        Output      = $outputPath
    }
}

# ---------------------------------------------------------------------------
# 4. Overall summary
# ---------------------------------------------------------------------------

Write-Host "======================================================"
Write-Host "BULK RUN COMPLETE - $($deviceSummaries.Count) device(s) processed"
Write-Host "======================================================"
$deviceSummaries | Format-Table Device, Total, Filled, NotAFinding, Open -AutoSize
Write-Host "Output folder: $OutputFolder"
Write-Host ""
Write-Host "IMPORTANT: Review every auto-filled rule against the actual"
Write-Host "config before submitting. These are heuristic regex checks,"
Write-Host "not authoritative compliance determinations."

Pause-Exit 0
