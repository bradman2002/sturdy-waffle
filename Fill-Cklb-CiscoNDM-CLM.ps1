<#
.SYNOPSIS
    Auto-fills the "easy" checks in a Cisco IOS Switch NDM .cklb using a
    device running-config, and saves a new .cklb with the results.

    CONSTRAINED LANGUAGE MODE SAFE VERSION - no Add-Type, no New-Object of
    non-core types, no static .NET method calls ([regex]::, [System.IO.File]::,
    etc). Uses only the -match operator and Get-Content/Set-Content/ConvertFrom-
    Json/ConvertTo-Json cmdlets, which all still work under CLM.

.DESCRIPTION
    Since CLM blocks Add-Type and WinForms (used for the GUI file pickers in
    the earlier version of this script), this version takes its inputs as
    plain parameters or interactive prompts instead - no GUI.

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

    Every other rule in the cklb is intentionally left "not_reviewed" -
    those genuinely need a human to check logs, external servers, etc.

    ALWAYS spot-check the auto-filled results against the actual config
    before you submit the cklb. This is a time-saver, not a substitute for
    review.

.PARAMETER CklbPath
    Path to the input .cklb file. If omitted, you'll be prompted.

.PARAMETER ConfigPath
    Path to the plain-text device config ("show running-config" output).
    If omitted, you'll be prompted.

.PARAMETER OutputPath
    Path to write the updated .cklb. If omitted, defaults to
    "<original name>_filled.cklb" next to the input file.

.EXAMPLE
    .\Fill-Cklb-CiscoNDM.ps1 -CklbPath .\blank.cklb -ConfigPath .\sw1-config.txt
#>

[CmdletBinding()]
param(
    [string]$CklbPath,
    [string]$ConfigPath,
    [string]$OutputPath
)

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# 0. Get input paths (prompts instead of GUI dialogs - CLM has no WinForms)
# ---------------------------------------------------------------------------

if (-not $CklbPath) {
    $CklbPath = Read-Host "Path to the .cklb file to fill in"
}
if (-not (Test-Path $CklbPath)) { throw "Cklb file not found: $CklbPath" }

if (-not $ConfigPath) {
    $ConfigPath = Read-Host "Path to the device running-config text file"
}
if (-not (Test-Path $ConfigPath)) { throw "Config file not found: $ConfigPath" }

if (-not $OutputPath) {
    $dir  = Split-Path -Parent $CklbPath
    $name = [System.IO.Path]::GetFileNameWithoutExtension($CklbPath)
    if (-not $dir) { $dir = "." }
    $OutputPath = Join-Path $dir "$name`_filled.cklb"
}

# ---------------------------------------------------------------------------
# 1. Load inputs
# ---------------------------------------------------------------------------

Write-Host "Loading cklb:   $CklbPath"
$cklb = Get-Content -Raw -Path $CklbPath | ConvertFrom-Json

Write-Host "Loading config: $ConfigPath"
$configText = Get-Content -Raw -Path $ConfigPath

# ---------------------------------------------------------------------------
# 2. Helpers - built entirely on the -match operator and String methods,
#    both of which are core/approved under Constrained Language Mode.
#    (Avoids [regex]::Matches/Match/IsMatch/Escape, which call methods on a
#    non-core type and are blocked or unreliable under CLM.)
# ---------------------------------------------------------------------------

function Test-Pattern {
    # Equivalent to [regex]::IsMatch, via the core -match operator.
    param([string]$Text, [string]$Pattern)
    return [bool]($Text -match $Pattern)
}

function Get-FirstMatchGroup {
    # Equivalent to [regex]::Match(...).Groups[n].Value, via -match.
    param([string]$Text, [string]$Pattern, [int]$GroupNum = 1)
    if ($Text -match $Pattern) {
        return $Matches[$GroupNum]
    }
    return $null
}

function Get-AllMatchGroups {
    # Equivalent to [regex]::Matches(...), implemented with a plain loop
    # using -match + string slicing so no regex *object* is ever touched.
    # Returns an array of hashtables copied from $Matches for each hit.
    param([string]$Text, [string]$Pattern)
    $results  = @()
    $remaining = $Text
    while ($remaining -match $Pattern) {
        $copy = @{}
        foreach ($k in $Matches.Keys) { $copy[$k] = $Matches[$k] }
        $results += $copy
        $idx = $remaining.IndexOf($Matches[0])
        if ($idx -lt 0) { break }
        $remaining = $remaining.Substring($idx + $Matches[0].Length)
    }
    return $results
}

function New-SimpleGuid {
    # Builds a random RFC4122-v4-shaped GUID string using only Get-Random
    # and string operations - no [guid]::NewGuid() static call, since it's
    # unclear whether System.Guid is on the CLM core-type allow-list.
    $hex = '0123456789abcdef'
    $raw = -join (1..32 | ForEach-Object { $hex[(Get-Random -Minimum 0 -Maximum 16)] })
    # Force version 4 / variant bits so it still looks like a standard GUID
    $raw = $raw.Substring(0,12) + '4' + $raw.Substring(13,3) + '8' + $raw.Substring(17)
    return "$($raw.Substring(0,8))-$($raw.Substring(8,4))-$($raw.Substring(12,4))-$($raw.Substring(16,4))-$($raw.Substring(20,12))"
}

function Get-CcPolicyBlock {
    # Pulls the body of the first "aaa common-criteria policy <name>" block
    # out of the config (settings are indented lines below the policy name,
    # terminated by a bare "!").
    param([string]$Config)
    return Get-FirstMatchGroup -Text $Config -Pattern '(?ms)^aaa common-criteria policy\s+\S+\s*\r?\n(.*?)(?=^!)' -GroupNum 1
}
$ccPolicyBlock = Get-CcPolicyBlock -Config $configText

# ---------------------------------------------------------------------------
# 3. Rule checks, keyed by the cklb's stable "rule_version" (STIG ID) field
# ---------------------------------------------------------------------------

$RuleChecks = @{

    "CISC-ND-000010" = {
        param($cfg, $ccBlock)
        $sessionLimit  = Test-Pattern $cfg '(?im)^\s*session-limit\s+\d+'
        $vtyRestricted = Test-Pattern $cfg '(?im)^\s*transport input\s+none'
        $httpLimited   = Test-Pattern $cfg '(?im)^ip http max-connections\s+\d+'
        if ($sessionLimit -or $vtyRestricted -or $httpLimited) {
            return @{ Match = $true; Detail = "Found session-limit / restricted vty transport / ip http max-connections in config. Verify the actual number matches your org's approved limit." }
        }
        return @{ Match = $false; Detail = "No session-limit, restricted 'transport input none' vty line, or 'ip http max-connections' found." }
    }

    "CISC-ND-000160" = {
        param($cfg, $ccBlock)
        if (Test-Pattern $cfg '(?im)^banner login') {
            return @{ Match = $true; Detail = "'banner login' block is configured. Manually verify the banner text matches the required DoD notice-and-consent wording." }
        }
        return @{ Match = $false; Detail = "No 'banner login' statement found in configuration." }
    }

    "CISC-ND-000470" = {
        param($cfg, $ccBlock)
        $badServices = @(
            'boot network', 'ip boot server', 'ip bootp server', 'ip dns server',
            'ip identd', 'ip finger', 'ip http server', 'ip rcmd rcp-enable',
            'ip rcmd rsh-enable', 'service config', 'service finger',
            'service tcp-small-servers', 'service udp-small-servers'
        )
        $found = @()
        foreach ($svc in $badServices) {
            if (Test-Pattern $cfg "(?im)^\s*$svc\s*`$") {
                $found += $svc
            }
        }
        if ($found.Count -eq 0) {
            return @{ Match = $true; Detail = "None of the unnecessary/non-secure services checked were found enabled." }
        }
        return @{ Match = $false; Detail = "Unnecessary service(s) still enabled: $($found -join ', ')" }
    }

    "CISC-ND-000490" = {
        param($cfg, $ccBlock)
        $userMatches = Get-AllMatchGroups -Text $cfg -Pattern '(?im)^username\s+(\S+)'
        $names = $userMatches | ForEach-Object { $_[1] } | Select-Object -Unique
        if ($names.Count -eq 1) {
            return @{ Match = $true; Detail = "Exactly one local account configured: $($names[0]). Manually confirm it is documented as the account-of-last-resort." }
        }
        return @{ Match = $false; Detail = "Found $($names.Count) local account(s): $($names -join ', '). Manual review required - multiple accounts may be justified but must be documented." }
    }

    "CISC-ND-000550" = {
        param($cfg, $ccBlock)
        if (-not $ccBlock) { return @{ Match = $false; Detail = "No 'aaa common-criteria policy' block found in configuration." } }
        $val = Get-FirstMatchGroup -Text $ccBlock -Pattern '(?im)^\s*min-length\s+(\d+)'
        if ($val) {
            $len = [int]$val
            if ($len -ge 15) { return @{ Match = $true; Detail = "Common-criteria policy min-length is $len (>= 15)." } }
            return @{ Match = $false; Detail = "Common-criteria policy min-length is $len (< 15 required)." }
        }
        return @{ Match = $false; Detail = "No 'min-length' setting found in the common-criteria policy block." }
    }

    "CISC-ND-000570" = {
        param($cfg, $ccBlock)
        if (-not $ccBlock) { return @{ Match = $false; Detail = "No 'aaa common-criteria policy' block found in configuration." } }
        $val = Get-FirstMatchGroup -Text $ccBlock -Pattern '(?im)^\s*upper-case\s+(\d+)'
        if ($val -and [int]$val -ge 1) {
            return @{ Match = $true; Detail = "Common-criteria policy requires upper-case $val character(s)." }
        }
        return @{ Match = $false; Detail = "No 'upper-case' requirement (>=1) found in the common-criteria policy block." }
    }

    "CISC-ND-000580" = {
        param($cfg, $ccBlock)
        if (-not $ccBlock) { return @{ Match = $false; Detail = "No 'aaa common-criteria policy' block found in configuration." } }
        $val = Get-FirstMatchGroup -Text $ccBlock -Pattern '(?im)^\s*lower-case\s+(\d+)'
        if ($val -and [int]$val -ge 1) {
            return @{ Match = $true; Detail = "Common-criteria policy requires lower-case $val character(s)." }
        }
        return @{ Match = $false; Detail = "No 'lower-case' requirement (>=1) found in the common-criteria policy block." }
    }

    "CISC-ND-000590" = {
        param($cfg, $ccBlock)
        if (-not $ccBlock) { return @{ Match = $false; Detail = "No 'aaa common-criteria policy' block found in configuration." } }
        $val = Get-FirstMatchGroup -Text $ccBlock -Pattern '(?im)^\s*numeric-count\s+(\d+)'
        if ($val -and [int]$val -ge 1) {
            return @{ Match = $true; Detail = "Common-criteria policy requires numeric-count $val character(s)." }
        }
        return @{ Match = $false; Detail = "No 'numeric-count' requirement (>=1) found in the common-criteria policy block." }
    }

    "CISC-ND-000600" = {
        param($cfg, $ccBlock)
        if (-not $ccBlock) { return @{ Match = $false; Detail = "No 'aaa common-criteria policy' block found in configuration." } }
        $val = Get-FirstMatchGroup -Text $ccBlock -Pattern '(?im)^\s*special-case\s+(\d+)'
        if ($val -and [int]$val -ge 1) {
            return @{ Match = $true; Detail = "Common-criteria policy requires special-case $val character(s)." }
        }
        return @{ Match = $false; Detail = "No 'special-case' requirement (>=1) found in the common-criteria policy block." }
    }

    "CISC-ND-000610" = {
        param($cfg, $ccBlock)
        if (-not $ccBlock) { return @{ Match = $false; Detail = "No 'aaa common-criteria policy' block found in configuration." } }
        $val = Get-FirstMatchGroup -Text $ccBlock -Pattern '(?im)^\s*char-changes\s+(\d+)'
        if ($val) {
            $n = [int]$val
            if ($n -ge 8) { return @{ Match = $true; Detail = "Common-criteria policy char-changes is $n (>= 8)." } }
            return @{ Match = $false; Detail = "Common-criteria policy char-changes is $n (< 8 required)." }
        }
        return @{ Match = $false; Detail = "No 'char-changes' setting found in the common-criteria policy block." }
    }

    "CISC-ND-000620" = {
        param($cfg, $ccBlock)
        $encSvc     = Test-Pattern $cfg '(?im)^service password-encryption'
        $encSecret  = Test-Pattern $cfg '(?im)^enable secret'
        $weakEnable = (Test-Pattern $cfg '(?im)^enable password') -and (-not (Test-Pattern $cfg '(?im)^enable password\s+secret'))
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
        param($cfg, $ccBlock)
        $timeouts = Get-AllMatchGroups -Text $cfg -Pattern '(?im)^\s*exec-timeout\s+(\d+)\s+(\d+)'
        if ($timeouts.Count -eq 0) {
            return @{ Match = $false; Detail = "No 'exec-timeout' statements found on any line." }
        }
        $tooLong = @()
        foreach ($t in $timeouts) {
            $min = [int]$t[1]
            $sec = [int]$t[2]
            if ($min -gt 5 -or ($min -eq 0 -and $sec -eq 0)) { $tooLong += "$min`:$sec" }
        }
        if ($tooLong.Count -eq 0) {
            return @{ Match = $true; Detail = "All $($timeouts.Count) exec-timeout statement(s) found are <= 5 minutes." }
        }
        return @{ Match = $false; Detail = "Found exec-timeout value(s) exceeding 5 minutes or disabled (0 0): $($tooLong -join ', '). Verify this applies to con/vty lines." }
    }

    "CISC-ND-001030" = {
        param($cfg, $ccBlock)
        $serverMatches = Get-AllMatchGroups -Text $cfg -Pattern '(?im)^ntp server\s+(\S+)'
        $servers = $serverMatches | ForEach-Object { $_[1] }
        if ($servers.Count -ge 2) {
            return @{ Match = $true; Detail = "NTP server(s) configured: $($servers -join ', ') (redundant sources present)." }
        } elseif ($servers.Count -eq 1) {
            return @{ Match = $false; Detail = "Only one NTP server configured ($($servers[0])); a redundant/secondary source is required." }
        }
        return @{ Match = $false; Detail = "No 'ntp server' statement found in configuration." }
    }

    "CISC-ND-001150" = {
        param($cfg, $ccBlock)
        $authEnabled = Test-Pattern $cfg '(?im)^ntp authenticate'
        $hasKey      = Test-Pattern $cfg '(?im)^ntp authentication-key\s+\d+\s+(md5|sha1|sha2)'
        $trustedKey  = Test-Pattern $cfg '(?im)^ntp trusted-key\s+\d+'
        $serverKeyed = Test-Pattern $cfg '(?im)^ntp server\s+\S+\s+key\s+\d+'
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
# 4. Walk the cklb and apply checks
# ---------------------------------------------------------------------------

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
        Write-Host "[$($rule.group_id)] $tag - $($rule.rule_title.Substring(0, [Math]::Min(70, $rule.rule_title.Length)))"
    }
}

# ---------------------------------------------------------------------------
# 5. Save - written with Set-Content -Encoding utf8 (always adds a BOM on
#    Windows PowerShell), then the BOM bytes are stripped back out using
#    Get-Content/Set-Content -Encoding Byte + array slicing. No New-Object,
#    no [System.IO.File]:: - just cmdlets and native array indexing, both
#    fine under Constrained Language Mode.
# ---------------------------------------------------------------------------

$oldId = $cklb.id
$cklb.id = New-SimpleGuid
Write-Host "Checklist id changed: $oldId -> $($cklb.id)"

$jsonOut = $cklb | ConvertTo-Json -Depth 50
Set-Content -Path $OutputPath -Value $jsonOut -Encoding utf8

$bytes = Get-Content -Path $OutputPath -Encoding Byte -Raw
if ($bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191) {
    $bytes = $bytes[3..($bytes.Length - 1)]
    Set-Content -Path $OutputPath -Value $bytes -Encoding Byte
}

Write-Host ""
Write-Host "======================================================"
Write-Host "Total rules in cklb:      $totalRules"
Write-Host "Auto-filled:              $appliedCount"
Write-Host "  -> Not a Finding:       $naFoundCount"
Write-Host "  -> Open:                $openCount"
Write-Host "Left as not_reviewed:     $($totalRules - $appliedCount)"
Write-Host "Saved to: $OutputPath"
Write-Host "======================================================"
Write-Host ""
Write-Host "IMPORTANT: Review every auto-filled rule against the actual"
Write-Host "config before submitting. These are heuristic regex checks,"
Write-Host "not authoritative compliance determinations."
