#Requires -Version 5.1
<#
.SYNOPSIS
    FEDLIN PQC Toolkit -- hardware posture collector (Windows)

.DESCRIPTION
    Emits a CycloneDX 1.6 component fragment for OS version, TPM presence, and HSM
    presence. Pair the output with merge-hw-cbom.py to insert the hardware components
    into your CBOM before running the report stage.

    This script is the hardware complement to collect-windows.ps1, which collects
    cryptographic assets (certs, AD CS, Schannel cipher suites). Run both.

    SECRET-SAFE BY CONSTRUCTION: reads Win32_OperatingSystem, Get-Tpm, tpmtool
    getdeviceinformation, service display names, and known PKCS#11 DLL install paths.
    Never reads private keys, certificate private-key material, PKCS#11 session state,
    or TPM key hierarchies. Do not add Get-PfxData, export, or credential reads here.

    Network appliances (Cisco ASA, Palo Alto, etc.) are NOT collected here -- their PQC
    posture is set by vendor firmware timelines. Add them manually as hw/net/* components
    using the sample-agency-cbom.json schema as a reference.

.PARAMETER Hostname
    FQDN or hostname for bom-ref and display name. Defaults to $env:COMPUTERNAME.

.PARAMETER Pretty
    Pretty-print JSON output (default: compact, suitable for piping to merge-hw-cbom.py).

.EXAMPLE
    .\collect-hardware-windows.ps1 -Hostname dc01.example.gov -Pretty
    .\collect-hardware-windows.ps1 | Out-File -Encoding UTF8 dc01-hw.json
    # then on the toolkit host:
    python3 merge-hw-cbom.py --cbom agency-cbom.json --hw dc01-hw.json
#>

[CmdletBinding()]
param(
    [string]$Hostname = $env:COMPUTERNAME,
    [switch]$Pretty
)

$ErrorActionPreference = "SilentlyContinue"   # hardware probes are best-effort
# Set-StrictMode intentionally omitted -- PS 7.4 strict mode generates terminating errors
# that bypass $ErrorActionPreference and silently swallow all output in run-command contexts.

try {

$components = [System.Collections.Generic.List[hashtable]]::new()

function New-Prop([string]$Name, [string]$Value) { return @{ name = $Name; value = $Value } }

function _Slugify([string]$s) {
    # bom-ref safe: lowercase alphanumeric, dot, hyphen
    return ($s.ToLower() -replace '[^a-z0-9.\-]', '-').Trim('-')
}

$bomRefHost = _Slugify $Hostname

# ============================================================================
# OS version / PQC classification
# ============================================================================

$os = Get-CimInstance -ClassName Win32_OperatingSystem
$osVersion = $os.Version    # e.g. "10.0.20348"
$osCaption = $os.Caption    # e.g. "Microsoft Windows Server 2022 Datacenter"
$osBuild   = [int](($osVersion -split '\.')[-1])

# Build-number -> Server version mapping.
# PQC-relevant boundary: Server 2025 (build 26100+) introduces PQC SChannel
# (ML-KEM via X25519MLKEM768) and PQC AD CS (ML-DSA certificate templates).
$serverLabel = switch ($osBuild) {
    { $_ -ge 26100 } { "Windows Server 2025"; break }
    { $_ -ge 20348 } { "Windows Server 2022"; break }
    { $_ -ge 17763 } { "Windows Server 2019"; break }
    default            { "Windows Server (pre-2019)" }
}

$pqcCapable = if ($osBuild -ge 26100) { "true" } else { "false" }
$hwPqcGate  = if ($pqcCapable -eq "true") { "false" } else { "true" }
$hwAction   = if ($pqcCapable -eq "true") { "configure" } else { "upgrade" }

if ($pqcCapable -eq "true") {
    $hwActionDetail = (
        "$serverLabel (build $osBuild) -- PQC SChannel (ML-KEM / X25519MLKEM768) and " +
        "PQC AD CS (ML-DSA certificate templates) are available. " +
        "Verify ML-DSA templates are published in AD CS and TLS 1.3 is not suppressed " +
        "via the SChannel registry key."
    )
} else {
    # Check whether AD CS is installed; if so, this host is the PKI migration gate
    $certSvc = Get-Service -Name CertSvc -ErrorAction SilentlyContinue
    $adcsNote = if ($certSvc) {
        " AD CS (CertSvc) is installed -- this is the PKI gate for all agency certificate migration."
    } else { "" }
    $hwActionDetail = (
        "PQC AD CS (ML-DSA) and PQC SChannel (ML-KEM) require Windows Server 2025 (build 26100+). " +
        "Current: $serverLabel (build $osBuild).$adcsNote"
    )
}

# TLS 1.3 status:
# Server 2019 (build <20348): TLS 1.3 not available in SChannel.
# Server 2022+ (build 20348+): TLS 1.3 enabled by default; can be explicitly disabled via registry.
$tls13Enabled = $false
if ($osBuild -ge 20348) {
    $tls13Enabled = $true   # default-on for Server 2022+
    $regKey = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server"
    if (Test-Path $regKey) {
        $enabledVal = (Get-ItemProperty -Path $regKey -Name Enabled -ErrorAction SilentlyContinue).Enabled
        if ($null -ne $enabledVal -and $enabledVal -eq 0) {
            $tls13Enabled = $false
        }
    }
}

$osProps = @(
    (New-Prop "fedlin:hw_class"        "os")
    (New-Prop "fedlin:host"             $Hostname)
    (New-Prop "fedlin:hw_pqc_capable"  $pqcCapable)
    (New-Prop "fedlin:hw_action"       $hwAction)
    (New-Prop "fedlin:hw_action_detail" $hwActionDetail)
    (New-Prop "fedlin:hw_pqc_gate"     $hwPqcGate)
    (New-Prop "fedlin:tls13_enabled"   $tls13Enabled.ToString().ToLower())
    (New-Prop "fedlin:os_build"        "$osBuild")
)

$components.Add(@{
    type       = "operating-system"
    "bom-ref"  = "hw/os/$bomRefHost"
    name       = "$osCaption -- $Hostname"
    version    = $osVersion
    properties = $osProps
})

# ============================================================================
# TPM
# ============================================================================

$tpmPresent = $false
$tpmVersion = "2.0"
$tpmVendor  = ""

try {
    $tpmObj = Get-Tpm -ErrorAction Stop
    $tpmPresent = [bool]$tpmObj.TpmPresent

    if ($tpmPresent) {
        # tpmtool is available on Server 2016+ for vendor/version detail.
        # Capture output as an array of strings; ignore non-zero exit code.
        $tpmtoolLines = @(& { tpmtool getdeviceinformation 2>$null } 2>$null)
        foreach ($line in $tpmtoolLines) {
            if ($line -match "Manufacturer Name[:\s]+(.+)") {
                $tpmVendor = $Matches[1].Trim()
            }
            if ($line -match "TPM Version[:\s]+([\d.]+)") {
                $tpmVersion = $Matches[1].Trim()
            }
        }
    }
} catch {}

if ($tpmPresent) {
    $tpmProps = [System.Collections.Generic.List[hashtable]]::new()
    $tpmProps.Add((New-Prop "fedlin:hw_class"        "tpm"))
    $tpmProps.Add((New-Prop "fedlin:host"             $Hostname))
    if ($tpmVendor) { $tpmProps.Add((New-Prop "fedlin:hw_vendor" $tpmVendor)) }
    $tpmProps.Add((New-Prop "fedlin:hw_pqc_capable"   "false"))
    $tpmProps.Add((New-Prop "fedlin:hw_action"        "replace"))
    $tpmProps.Add((New-Prop "fedlin:hw_action_detail" (
        "Existing discrete TPM cannot perform ML-KEM or ML-DSA as general operations. " +
        "No firmware path for PQC general ops exists for current-gen discrete TPMs. " +
        "Replace at next scheduled hardware refresh (2028-2030 lifecycle)."
    )))
    $tpmProps.Add((New-Prop "fedlin:hw_fips_status" (
        "FIPS 140-2 validated (TPM 2.0 profile); " +
        "no FIPS 140-3 PQC validation exists for discrete TPMs"
    )))

    $components.Add(@{
        type       = "device"
        "bom-ref"  = "hw/tpm/$bomRefHost"
        name       = "TPM $tpmVersion -- $Hostname"
        version    = $tpmVersion
        properties = $tpmProps.ToArray()
    })
}

# ============================================================================
# HSM detection (service names + PKCS#11 DLL paths; no key access)
# ============================================================================

$hsmFound       = $false
$hsmDisplayName = ""

# Service-name patterns for common HSM vendors
$hsmSvcPatterns = @("safenet", "luna", "nethsm", "nshield", "thales", "utimaco", "securosys", "primus", "proteccio")
foreach ($svc in (Get-Service -ErrorAction SilentlyContinue)) {
    $n = $svc.Name.ToLower()
    foreach ($pat in $hsmSvcPatterns) {
        if ($n -like "*$pat*") {
            $hsmFound = $true
            $hsmDisplayName = $svc.DisplayName
            break
        }
    }
    if ($hsmFound) { break }
}

# PKCS#11 DLL install paths (presence check only -- no DLL loading)
if (-not $hsmFound) {
    $pkcs11Paths = @(
        "$env:ProgramFiles\SafeNet\LunaClient\cryptoki.dll",
        "$env:ProgramFiles\SafeNet\LunaClient\multitoken\cryptoki.dll",
        "$env:ProgramFiles\nCipher\nfast\bin\cknfast.dll",
        "$env:ProgramFiles\Thales\Luna PCI-E\lib\cryptoki.dll",
        "$env:ProgramFiles\Utimaco\Software\pkcs11\cryptoki.dll",
        "$env:ProgramFiles\Securosys\Primus\PKCS11\Primus.PKCS11.dll"
    )
    foreach ($dll in $pkcs11Paths) {
        if (Test-Path $dll) {
            $hsmFound = $true
            $hsmDisplayName = "HSM PKCS#11 library at $(Split-Path $dll -Parent)"
            break
        }
    }
}

if ($hsmFound) {
    $components.Add(@{
        type       = "device"
        "bom-ref"  = "hw/hsm/$bomRefHost"
        name       = "HSM -- $Hostname ($hsmDisplayName)"
        properties = @(
            (New-Prop "fedlin:hw_class"        "hsm")
            (New-Prop "fedlin:host"             $Hostname)
            (New-Prop "fedlin:hw_pqc_capable"  "unknown")
            (New-Prop "fedlin:hw_action"       "configure")
            (New-Prop "fedlin:hw_action_detail" (
                "HSM detected ($hsmDisplayName). Verify FIPS 140-3 CMVP validation status " +
                "for PQC operations (ML-KEM-1024 / ML-DSA-87). " +
                "Currently validated: Thales TCT Luna T7 (CMVP #5450). " +
                "Analyst must confirm product version and CMVP certificate number " +
                "before marking PQC-capable."
            ))
            (New-Prop "fedlin:hw_fips_status"  "analyst verification required -- see action detail")
        )
    })
} else {
    $components.Add(@{
        type       = "device"
        "bom-ref"  = "hw/hsm/absent-$bomRefHost"
        name       = "HSM -- not detected on $Hostname"
        properties = @(
            (New-Prop "fedlin:hw_class"        "hsm")
            (New-Prop "fedlin:host"             $Hostname)
            (New-Prop "fedlin:hw_pqc_capable"  "false")
            (New-Prop "fedlin:hw_action"       "procure")
            (New-Prop "fedlin:hw_action_detail" (
                "No HSM detected. PQC key establishment (ML-KEM-1024) requires a " +
                "FIPS 140-3 CMVP-validated HSM. Currently one product meets this bar: " +
                "Thales TCT Luna T7 (CMVP cert #5450). Additional products in CMVP " +
                "pipeline (Entrust nShield 5, Securosys Primus): expected 2027-2028."
            ))
            (New-Prop "fedlin:hw_pqc_gate"    "true")
            (New-Prop "fedlin:hw_fips_status" "n/a -- no HSM detected")
        )
    })
}

# ============================================================================
# Output
# ============================================================================

$output = @{ components = $components.ToArray() }

# Write UTF-8 without BOM. ConvertTo-Json -Compress (PS 7+) or pretty-print (PS 5.1 fallback).
[System.Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

if ($Pretty) {
    Write-Output ($output | ConvertTo-Json -Depth 10)
} else {
    # -Compress is available in PS 3.0+ (including 5.1 and 7.x).
    # Azure run-command truncates stdout to the last 4096 bytes; compact JSON is essential.
    Write-Output ($output | ConvertTo-Json -Depth 10 -Compress)
}

} catch {
    # Emit error as JSON so it surfaces in the run-command [stdout] block and is debuggable.
    [System.Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
    $errLine = $_.InvocationInfo.ScriptLineNumber
    $errMsg  = $_.Exception.Message -replace '"', "'"
    Write-Output "{`"error`": `"$errMsg`", `"line`": $errLine, `"ps_version`": `"$($PSVersionTable.PSVersion)`"}"
}
