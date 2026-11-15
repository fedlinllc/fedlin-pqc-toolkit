<#
.SYNOPSIS
  FEDLIN PQC Toolkit -- Windows / AD-CS crypto collector (Windows edition).

.DESCRIPTION
  Closes the SS5.2 Windows/AD-CS coverage gap. The Linux toolkit cannot read Windows crypto
  stores or AD-CS, so this runs ON the Windows host and emits a CycloneDX 1.6 CBOM that folds
  straight into the toolkit via `--merge-cbom` (the universal overlay then applies CNSA 2.0
  verdicts to everything it emits).

  SECRET-SAFE BY CONSTRUCTION: reads PUBLIC certificate metadata (subject/issuer/validity/
  public-key algorithm/size/signature algorithm), Schannel protocol + cipher-suite policy, and
  AD-CS CA configuration ONLY. It never exports a private key or a secret value. Do not add
  Export-PfxCertificate, private-key export, or credential reads here.

  Covers:
   * Machine certificate stores (LocalMachine\My, \CA, \Root) -- public metadata + algorithms
   * AD-CS Certification Authority (if the CertSvc role is present) -- CA cert, signing algorithm,
     published certificate templates
   * Schannel TLS policy -- enabled protocols and cipher suites (registry / Get-TlsCipherSuite)

.PARAMETER OutFile
  Path to write the CycloneDX 1.6 CBOM JSON (default: .\windows-cbom.json).

.PARAMETER SystemName
  Logical system name recorded in the CBOM metadata (default: the machine hostname).

.PARAMETER IncludeRootStore
  Also inventory the Root/CA trust stores (large; off by default -- identity certs are in \My).

.EXAMPLE
  .\collect-windows.ps1 -OutFile C:\temp\dc01-cbom.json -SystemName "AGENCY-DC01"
  # then on the toolkit host:  python3 tier2_pipeline.py --no-runtime --merge-cbom dc01-cbom.json --report
#>
[CmdletBinding()]
param(
    [string]$OutFile = ".\windows-cbom.json",
    [string]$SystemName = $env:COMPUTERNAME,
    [switch]$IncludeRootStore
)

$ErrorActionPreference = "Stop"
$components = New-Object System.Collections.ArrayList
$algoSeen   = @{}

function Add-Algorithm {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return }
    # normalize to identifiers the CNSA 2.0 ruleset recognizes (friendly names, not OIDs)
    $n = $Name.Trim()
    switch -Regex ($n) {
        '^ECC$'                { $n = 'ECDSA' }        # CNG key store reports EC keys as "ECC"
        '^ECDSA_'              { $n = 'ECDSA' }        # ECDSA_P256 / _P384 -> ECDSA
        '^ECDH_'               { $n = 'ECDH' }
        '^1\.2\.840\.10045'    { $n = 'ECDSA' }        # ecPublicKey OID fallback
        '^1\.2\.840\.113549\.1\.1' { $n = 'RSA' }      # rsaEncryption OID fallback
    }
    $key = $n.ToLower()
    if ($algoSeen.ContainsKey($key)) { return }
    $algoSeen[$key] = $true
    $slug = ($n.ToLower() -replace '[^a-z0-9]+','-').Trim('-')
    [void]$components.Add([ordered]@{
        type = "cryptographic-asset"
        "bom-ref" = "win/algo/$slug"
        name = $n
        cryptoProperties = [ordered]@{
            assetType = "algorithm"
            algorithmProperties = [ordered]@{ primitive = "unknown"; cryptoFunctions = @("unknown") }
        }
        properties = @(@{ name = "fedlin:source"; value = "windows-collector" })
    })
}

function Add-Certificate {
    param($Cert, [string]$StoreLabel)
    $subject = $Cert.Subject
    $keyAlg  = $null; $keySize = $null
    try { $keyAlg = $Cert.PublicKey.Oid.FriendlyName } catch {}
    try { $keySize = $Cert.PublicKey.Key.KeySize } catch {}
    if (-not $keySize) { try { $keySize = ([Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($Cert)).KeySize } catch {} }
    $sigAlg  = $Cert.SignatureAlgorithm.FriendlyName
    $slug = ($Cert.Thumbprint.ToLower())
    $certProps = [ordered]@{
        subjectName = "$subject"
        issuerName  = "$($Cert.Issuer)"
        certificateFormat = "X.509"
        notValidBefore = $Cert.NotBefore.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        notValidAfter  = $Cert.NotAfter.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
    [void]$components.Add([ordered]@{
        type = "cryptographic-asset"
        "bom-ref" = "win/cert/$slug"
        name = ($subject -replace '^CN=','' -replace ',.*$','')
        cryptoProperties = [ordered]@{ assetType = "certificate"; certificateProperties = $certProps }
        properties = @(
            @{ name = "fedlin:source"; value = "windows-collector ($StoreLabel)" },
            @{ name = "fedlin:key_size"; value = "$keySize" }
        )
    })
    Add-Algorithm $keyAlg
    Add-Algorithm $sigAlg
}

# ---- 1. machine certificate stores (public metadata only) ----
$stores = @("My", "CA")
if ($IncludeRootStore) { $stores += "Root" }
foreach ($store in $stores) {
    $path = "Cert:\LocalMachine\$store"
    if (Test-Path $path) {
        Get-ChildItem $path -ErrorAction SilentlyContinue | ForEach-Object { Add-Certificate $_ $store }
    }
}

# ---- 2. AD-CS Certification Authority (best-effort; only if the role is present) ----
$adcsProps = @{}
$certSvc = Get-Service -Name CertSvc -ErrorAction SilentlyContinue
if ($certSvc) {
    $adcsProps["fedlin:adcs_role"] = "present ($($certSvc.Status))"
    try {
        $caName = (& certutil -getreg CA\CommonName 2>$null | Select-String -Pattern 'CommonName REG_SZ = (.+)$').Matches.Groups[1].Value
        if ($caName) { $adcsProps["fedlin:adcs_ca_name"] = $caName.Trim() }
        # CA signing hash/provider -- quantum-relevant: SHA1-signing CAs are a critical finding
        $caHash = (& certutil -getreg CA\CNGHashAlgorithm 2>$null | Select-String -Pattern 'REG_SZ = (.+)$').Matches.Groups[1].Value
        if ($caHash) { $adcsProps["fedlin:adcs_signing_hash"] = $caHash.Trim(); Add-Algorithm $caHash.Trim() }
        # published templates (names only)
        $templates = & certutil -CATemplates 2>$null | Select-String -Pattern '^\s*(\S+):' | ForEach-Object { $_.Matches.Groups[1].Value }
        if ($templates) { $adcsProps["fedlin:adcs_templates"] = ($templates -join ", ") }
    } catch {
        $adcsProps["fedlin:adcs_note"] = "CA present but certutil enumeration failed (run as an AD-CS admin for full detail)"
    }
} else {
    $adcsProps["fedlin:adcs_role"] = "not a CA (no CertSvc)"
}

# ---- 3. Schannel TLS policy (enabled protocols + cipher suites) ----
$schannelProps = @{}
$protoBase = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
$enabledProtos = New-Object System.Collections.ArrayList
foreach ($proto in @("SSL 2.0","SSL 3.0","TLS 1.0","TLS 1.1","TLS 1.2","TLS 1.3")) {
    $sk = "$protoBase\$proto\Server"
    if (Test-Path $sk) {
        $enabled = (Get-ItemProperty $sk -Name Enabled -ErrorAction SilentlyContinue).Enabled
        $disabledByDefault = (Get-ItemProperty $sk -Name DisabledByDefault -ErrorAction SilentlyContinue).DisabledByDefault
        # Only report a protocol as EXPLICITLY enabled when the Enabled DWORD is present and non-zero.
        # An absent value ($null) means "OS default", NOT enabled -- never count $null as enabled.
        if ($null -ne $enabled -and $enabled -ne 0 -and $disabledByDefault -ne 1) { [void]$enabledProtos.Add($proto) }
        if (($proto -eq "SSL 2.0" -or $proto -eq "SSL 3.0" -or $proto -eq "TLS 1.0" -or $proto -eq "TLS 1.1") -and $enabled -eq 1) {
            Add-Algorithm $proto  # legacy protocol explicitly enabled -- surfaces as a finding
        }
    }
}
if ($enabledProtos.Count) { $schannelProps["fedlin:schannel_protocols"] = ($enabledProtos -join ", ") }

# cipher suites (Get-TlsCipherSuite on 2016+/Win10+; each suite name classifies via the ruleset).
# Falls back to the registry-configured suite order if the cmdlet is unavailable (e.g. constrained
# runspace / Server Core module gaps), and records the real error rather than assuming a Windows version.
$suites = $null
try {
    $suites = Get-TlsCipherSuite -ErrorAction Stop | Select-Object -ExpandProperty Name
} catch {
    $regFns = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002"
    if (Test-Path $regFns) {
        $suites = (Get-ItemProperty $regFns -Name Functions -ErrorAction SilentlyContinue).Functions
    }
    if (-not $suites) {
        $schannelProps["fedlin:schannel_note"] = "cipher policy not enumerated: $($_.Exception.Message)"
    } else {
        $schannelProps["fedlin:schannel_note"] = "cipher suites read from registry (Get-TlsCipherSuite unavailable: $($_.Exception.Message))"
    }
}
if ($suites) {
    $schannelProps["fedlin:tls_cipher_count"] = "$(@($suites).Count)"
    foreach ($s in @($suites)) { Add-Algorithm $s }
}

# ---- assemble CycloneDX 1.6 ----
$ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$metaProps = @()
foreach ($h in @($adcsProps, $schannelProps)) {
    foreach ($k in $h.Keys) { $metaProps += @{ name = $k; value = "$($h[$k])" } }
}
$metaProps += @{ name = "fedlin:platform"; value = "windows" }
$metaProps += @{ name = "fedlin:collector"; value = "collect-windows.ps1" }

$bom = [ordered]@{
    bomFormat = "CycloneDX"
    specVersion = "1.6"
    serialNumber = "urn:uuid:$([guid]::NewGuid().ToString())"
    version = 1
    metadata = [ordered]@{
        timestamp = $ts
        component = [ordered]@{ type = "platform"; name = $SystemName; "bom-ref" = "system" }
        tools = [ordered]@{ components = @([ordered]@{ type = "application"; name = "fedlin-pqc-toolkit"; version = "windows-collector 0.1"; publisher = "FEDLIN" }) }
        properties = $metaProps
    }
    components = @($components)
}

$json = $bom | ConvertTo-Json -Depth 12
# Write UTF-8 WITHOUT a BOM. PS 5.1's `Set-Content -Encoding UTF8` prepends a BOM that breaks a
# plain json.load on the consuming side (only cyclonedx-cli tolerates it). .NET UTF8Encoding($false)
# is BOM-less and works on both PS 5.1 and 7+.
[System.IO.File]::WriteAllText($OutFile, $json, (New-Object System.Text.UTF8Encoding($false)))
$certCount = @($components | Where-Object { $_.cryptoProperties.assetType -eq "certificate" }).Count
$algoCount = @($components | Where-Object { $_.cryptoProperties.assetType -eq "algorithm" }).Count
Write-Host "[ok] wrote $OutFile -- $certCount certificate(s), $algoCount algorithm(s) for CNSA 2.0 overlay"
Write-Host "[next] on the toolkit host: python3 tier2_pipeline.py --no-runtime --merge-cbom $OutFile --report --regime CMMC"
