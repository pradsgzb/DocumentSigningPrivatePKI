#requires -Version 5.1
<#
.SYNOPSIS
    Creates and operates a two-tier private PKI for PDF and Microsoft Office
    document-signing certificates by using OpenSSL 3.x.

.DESCRIPTION
    This script intentionally separates the offline Root CA from the Issuing CA.
    Use the staged actions in this order:

      1. InitializeRoot          (offline Root CA computer)
      2. CreateIssuingRequest    (Issuing CA computer)
      3. SignIssuingRequest      (offline Root CA computer)
      4. FinalizeIssuing         (Issuing CA computer)
      5. IssueDocumentSigner     (Issuing CA computer)

    Additional actions generate CRLs, revoke certificates, verify chains, and
    install public trust or a signer PFX into Windows certificate stores.

    This creates a PRIVATE PKI. Its signatures are not automatically trusted by
    arbitrary external recipients, Adobe AATL, Microsoft Trusted Root Program,
    or an eIDAS trust list. Trust must be deployed to relying computers or a
    certificate must be purchased from a public trust-service provider.

.NOTES
    Cryptographic profile:
      - Root CA: RSA 4096, SHA-384, 20-year default validity, pathLen 1
      - Issuing CA: RSA 4096, SHA-384, 10-year default validity, pathLen 0
      - Document signer: RSA 3072, SHA-256, 2-year default validity
      - Encrypted PKCS#8 private keys (AES-256-CBC)
      - PKCS#12/PFX export using AES-256-CBC, HMAC-SHA-256, PBKDF2
      - CRLs for both CA tiers
      - Document-signing EKUs:
          IETF RFC 9336:             1.3.6.1.5.5.7.3.36
          Microsoft Office:         1.3.6.1.4.1.311.10.3.12
          Adobe document signing:   1.2.840.113583.1.1.5

    For high-assurance production use, place CA and signer keys in approved HSMs
    or hardware tokens, retain the Root CA offline, publish CRLs reliably, use a
    trusted RFC 3161 timestamp service, and operate under approved PKI policies.

.EXAMPLE
    .\PrivateDocumentPki.ps1 InitializeRoot `
      -RootCaPath 'D:\PKI\OfflineRoot' `
      -PkiBaseUrl 'http://pki.example.org/document-pki' `
      -Organization 'Example Medical Clinic, PA' `
      -StateOrProvince 'North Carolina' `
      -Locality 'Fayetteville'

.EXAMPLE
    .\PrivateDocumentPki.ps1 CreateIssuingRequest `
      -IssuingCaPath 'D:\PKI\IssuingCA' `
      -TransferPath 'E:\PKI-Transfer' `
      -PkiBaseUrl 'http://pki.example.org/document-pki' `
      -Organization 'Example Medical Clinic, PA' `
      -StateOrProvince 'North Carolina' `
      -Locality 'Fayetteville'

.EXAMPLE
    .\PrivateDocumentPki.ps1 IssueDocumentSigner `
      -IssuingCaPath 'D:\PKI\IssuingCA' `
      -IssuedPath 'D:\PKI\Issued' `
      -SignerCommonName 'Nitinchandra Desai, MD' `
      -SignerEmail 'dr.desai@example.org' `
      -SignerTitle 'Principal Investigator'
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet(
        'InitializeRoot',
        'CreateIssuingRequest',
        'SignIssuingRequest',
        'FinalizeIssuing',
        'IssueDocumentSigner',
        'GenerateRootCrl',
        'GenerateIssuingCrl',
        'RevokeDocumentSigner',
        'RevokeIssuingCA',
        'VerifyDocumentSigner',
        'InstallTrust',
        'InstallSignerPfx'
    )]
    [string] $Action,

    [string] $OpenSslPath = 'openssl.exe',

    [string] $RootCaPath = 'C:\PrivatePKI\RootCA',
    [string] $IssuingCaPath = 'C:\PrivatePKI\IssuingCA',
    [string] $TransferPath = 'C:\PrivatePKI\Transfer',
    [string] $IssuedPath = 'C:\PrivatePKI\Issued',
    [string] $BundlePath,

    [string] $PkiBaseUrl,
    [string] $OcspUrl,

    [ValidatePattern('^[A-Za-z]{2}$')]
    [string] $Country = 'US',

    [string] $StateOrProvince,
    [string] $Locality,
    [string] $Organization,
    [string] $RootOrganizationalUnit = 'Public Key Infrastructure',
    [string] $IssuingOrganizationalUnit = 'Document Signing',
    [string] $RootCommonName,
    [string] $IssuingCommonName,

    [string] $SignerCommonName,
    [string] $SignerEmail,
    [string] $SignerTitle,
    [string] $SignerOrganization,
    [string] $SignerOrganizationalUnit = 'Document Signing',

    [string] $CertificatePath,
    [string] $PfxPath,
    [string] $ExpectedRootFingerprint,

    [ValidateSet(
        'unspecified',
        'keyCompromise',
        'CACompromise',
        'affiliationChanged',
        'superseded',
        'cessationOfOperation',
        'certificateHold'
    )]
    [string] $RevocationReason = 'keyCompromise',

    [ValidateSet('CurrentUser', 'LocalMachine')]
    [string] $TrustScope = 'CurrentUser',

    [ValidateRange(3650, 9131)]
    [int] $RootValidityDays = 7305,

    [ValidateRange(1825, 5479)]
    [int] $IssuingValidityDays = 3652,

    [ValidateRange(30, 1095)]
    [int] $SignerValidityDays = 730,

    [ValidateRange(7, 730)]
    [int] $RootCrlDays = 365,

    [ValidateRange(1, 30)]
    [int] $IssuingCrlDays = 7,

    [ValidateRange(10000, 1000000)]
    [int] $PfxIterations = 200000,

    [switch] $SkipPfx
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$script:InvocationBoundParameters = @{}
foreach ($parameterName in $PSBoundParameters.Keys) {
    $script:InvocationBoundParameters[$parameterName] = $PSBoundParameters[$parameterName]
}

$script:OpenSslExecutable = $null
$script:OpenSslVersion = $null
$script:SupportsPfxMacSaltLength = $false
$script:IsWindowsPlatform = ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT)
$script:Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Write-Section {
    param([Parameter(Mandatory = $true)][string] $Text)
    Write-Host ''
    Write-Host ('=' * 78)
    Write-Host $Text
    Write-Host ('=' * 78)
}

function Assert-RequiredValue {
    param(
        [Parameter(Mandatory = $true)][string] $Name,
        [AllowEmptyString()][string] $Value
    )
    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw "Parameter -$Name is required for action '$Action'."
    }
}

function Assert-NoNewLine {
    param(
        [Parameter(Mandatory = $true)][string] $Name,
        [AllowEmptyString()][string] $Value
    )
    if ($null -ne $Value -and $Value -match "[\r\n]") {
        throw "Value '$Name' must not contain CR or LF characters."
    }
}

function Write-Utf8File {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string] $Content
    )
    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        [System.IO.Directory]::CreateDirectory($parent) | Out-Null
    }
    [System.IO.File]::WriteAllText($Path, $Content, $script:Utf8NoBom)
}

function Write-AsciiFile {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string] $Content
    )
    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        [System.IO.Directory]::CreateDirectory($parent) | Out-Null
    }
    [System.IO.File]::WriteAllText($Path, $Content, [System.Text.Encoding]::ASCII)
}

function ConvertTo-OpenSslPath {
    param([Parameter(Mandatory = $true)][string] $Path)
    return [System.IO.Path]::GetFullPath($Path).Replace('\', '/')
}

function Quote-OpenSslConfigValue {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string] $Value)
    Assert-NoNewLine -Name 'OpenSSL configuration value' -Value $Value
    $escaped = $Value.Replace('\', '\\').Replace('"', '\"').Replace('$', '\$')
    return '"' + $escaped + '"'
}

function Test-AbsoluteHttpUrl {
    param(
        [Parameter(Mandatory = $true)][string] $Name,
        [Parameter(Mandatory = $true)][string] $Value
    )
    $uri = $null
    if (-not [System.Uri]::TryCreate($Value, [System.UriKind]::Absolute, [ref] $uri)) {
        throw "$Name must be an absolute HTTP or HTTPS URL."
    }
    if ($uri.Scheme -notin @('http', 'https')) {
        throw "$Name must use HTTP or HTTPS."
    }
    if (-not [string]::IsNullOrWhiteSpace($uri.UserInfo)) {
        throw "$Name must not contain embedded credentials."
    }
    if (-not [string]::IsNullOrWhiteSpace($uri.Query) -or -not [string]::IsNullOrWhiteSpace($uri.Fragment)) {
        throw "$Name must not contain a query string or fragment."
    }
    if ($Value -match '[,\s]') {
        throw "$Name must not contain whitespace or a comma."
    }
    foreach ($unsafeCharacter in @('$', '"', "'", '\')) {
        if ($Value.Contains($unsafeCharacter)) {
            throw "$Name contains a character that is unsafe in an OpenSSL configuration value: $unsafeCharacter"
        }
    }
}

function Normalize-PkiBaseUrl {
    param([Parameter(Mandatory = $true)][string] $Value)
    Test-AbsoluteHttpUrl -Name 'PkiBaseUrl' -Value $Value
    return $Value.TrimEnd('/')
}

function New-RandomHex {
    param([ValidateRange(8, 64)][int] $Bytes = 16)
    $buffer = New-Object byte[] $Bytes
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($buffer)
    }
    finally {
        $rng.Dispose()
    }
    $buffer[0] = $buffer[0] -band 0x7F
    if (($buffer | Where-Object { $_ -ne 0 }).Count -eq 0) {
        $buffer[$buffer.Length - 1] = 1
    }
    return (($buffer | ForEach-Object { $_.ToString('X2') }) -join '')
}

function Get-SafeFileName {
    param([Parameter(Mandatory = $true)][string] $Value)
    $safe = $Value.ToLowerInvariant()
    $safe = [System.Text.RegularExpressions.Regex]::Replace($safe, '[^a-z0-9]+', '-')
    $safe = $safe.Trim('-')
    if ([string]::IsNullOrWhiteSpace($safe)) {
        $safe = 'document-signer'
    }
    if ($safe.Length -gt 60) {
        $safe = $safe.Substring(0, 60).TrimEnd('-')
    }
    return $safe
}

function Test-IsAdministrator {
    if (-not $script:IsWindowsPlatform) {
        return $false
    }
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Set-RestrictedAcl {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [switch] $Directory,
        [switch] $IncludeAdministrators
    )
    if (-not $script:IsWindowsPlatform) {
        Write-Warning "ACL hardening was skipped because this is not Windows: $Path"
        return
    }
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Cannot set ACL because path does not exist: $Path"
    }

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $grantArgs = @()
    if ($Directory) {
        $grantArgs += "${identity}:(OI)(CI)F"
        $grantArgs += '*S-1-5-18:(OI)(CI)F'
        if ($IncludeAdministrators) {
            $grantArgs += '*S-1-5-32-544:(OI)(CI)F'
        }
    }
    else {
        $grantArgs += "${identity}:F"
        $grantArgs += '*S-1-5-18:F'
        if ($IncludeAdministrators) {
            $grantArgs += '*S-1-5-32-544:F'
        }
    }

    $arguments = @($Path, '/inheritance:r', '/grant:r') + $grantArgs + @('/Q')
    $output = & icacls.exe @arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to apply restricted ACL to '$Path'. icacls output: $($output -join [Environment]::NewLine)"
    }
}

function ConvertFrom-SecureStringToPlainText {
    param([Parameter(Mandatory = $true)][Security.SecureString] $SecureString)
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Read-ValidatedPassphrase {
    param(
        [Parameter(Mandatory = $true)][string] $Prompt,
        [ValidateRange(12, 128)][int] $MinimumLength = 20
    )
    while ($true) {
        $first = Read-Host -Prompt $Prompt -AsSecureString
        $second = Read-Host -Prompt 'Confirm the passphrase' -AsSecureString
        $firstPlain = $null
        $secondPlain = $null
        try {
            $firstPlain = ConvertFrom-SecureStringToPlainText -SecureString $first
            $secondPlain = ConvertFrom-SecureStringToPlainText -SecureString $second

            if ($firstPlain -cne $secondPlain) {
                Write-Warning 'The passphrases did not match. Try again.'
                continue
            }
            if ($firstPlain.Length -lt $MinimumLength) {
                Write-Warning "Use at least $MinimumLength characters."
                continue
            }
            if ($firstPlain -match "[\r\n]") {
                Write-Warning 'CR and LF characters are not allowed in passphrases.'
                continue
            }
            $invalidCharacters = @($firstPlain.ToCharArray() | Where-Object { [int] $_ -lt 32 -or [int] $_ -gt 126 })
            if ($invalidCharacters.Count -gt 0) {
                Write-Warning 'For PKCS#12 interoperability, use printable ASCII characters only.'
                continue
            }
            return $first
        }
        finally {
            $firstPlain = $null
            $secondPlain = $null
        }
    }
}

function New-TemporarySecretFile {
    param(
        [Parameter(Mandatory = $true)][Security.SecureString] $Secret,
        [Parameter(Mandatory = $true)][string] $Label
    )
    $directory = Join-Path ([System.IO.Path]::GetTempPath()) ('private-pki-' + [Guid]::NewGuid().ToString('N'))
    [System.IO.Directory]::CreateDirectory($directory) | Out-Null
    Set-RestrictedAcl -Path $directory -Directory

    $path = Join-Path $directory ($Label + '.secret')
    $plain = $null
    try {
        $plain = ConvertFrom-SecureStringToPlainText -SecureString $Secret
        [System.IO.File]::WriteAllText($path, $plain, $script:Utf8NoBom)
        Set-RestrictedAcl -Path $path
    }
    finally {
        $plain = $null
    }
    return $path
}

function Remove-TemporarySecretFile {
    param([AllowNull()][string] $Path)
    if ([string]::IsNullOrWhiteSpace($Path)) {
        return
    }
    try {
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            $length = (Get-Item -LiteralPath $Path).Length
            if ($length -gt 0 -and $length -lt 1048576) {
                $buffer = New-Object byte[] ([int] $length)
                $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
                try {
                    $rng.GetBytes($buffer)
                    [System.IO.File]::WriteAllBytes($Path, $buffer)
                }
                finally {
                    $rng.Dispose()
                }
            }
            Remove-Item -LiteralPath $Path -Force
        }
        $directory = Split-Path -Parent $Path
        if (Test-Path -LiteralPath $directory -PathType Container) {
            Remove-Item -LiteralPath $directory -Force -Recurse
        }
    }
    catch {
        Write-Warning "Could not fully remove temporary secret file '$Path': $($_.Exception.Message)"
    }
}

function Get-OpenSslPasswordSource {
    param([Parameter(Mandatory = $true)][string] $SecretFilePath)
    return 'file:' + (ConvertTo-OpenSslPath -Path $SecretFilePath)
}

function Resolve-OpenSsl {
    $command = Get-Command -Name $OpenSslPath -ErrorAction SilentlyContinue
    if ($null -eq $command) {
        if (-not (Test-Path -LiteralPath $OpenSslPath -PathType Leaf)) {
            throw "OpenSSL was not found. Install a vetted OpenSSL 3.x build and supply -OpenSslPath. Requested path/name: $OpenSslPath"
        }
        $script:OpenSslExecutable = [System.IO.Path]::GetFullPath($OpenSslPath)
    }
    else {
        if ($command -is [System.Management.Automation.ApplicationInfo]) {
            $script:OpenSslExecutable = $command.Path
        }
        elseif (-not [string]::IsNullOrWhiteSpace([string] $command.Source)) {
            $script:OpenSslExecutable = $command.Source
        }
        else {
            throw "OpenSSL command resolution did not return an executable path for '$OpenSslPath'."
        }
    }

    $versionOutput = & $script:OpenSslExecutable version 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to run OpenSSL: $($versionOutput -join [Environment]::NewLine)"
    }
    $script:OpenSslVersion = ($versionOutput -join ' ').Trim()
    if ($script:OpenSslVersion -notmatch '^OpenSSL\s+(?<major>\d+)\.(?<minor>\d+)') {
        throw "Unrecognized OpenSSL version output: $script:OpenSslVersion"
    }
    if ([int] $Matches.major -lt 3) {
        throw "OpenSSL 3.0 or later is required. Detected: $script:OpenSslVersion"
    }

    $pkcs12Help = & $script:OpenSslExecutable pkcs12 -help 2>&1
    $script:SupportsPfxMacSaltLength = (($pkcs12Help -join ' ') -match '(?<!\S)-macsaltlen(?!\S)')
}

function Invoke-OpenSsl {
    param(
        [Parameter(Mandatory = $true)][string[]] $Arguments,
        [Parameter(Mandatory = $true)][string] $Description,
        [switch] $PassThru
    )
    Write-Verbose ("OpenSSL: {0}" -f ($Arguments -join ' '))
    $output = & $script:OpenSslExecutable @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "OpenSSL failed while $Description (exit code $exitCode).`n$($output -join [Environment]::NewLine)"
    }
    if ($PassThru) {
        return ($output -join [Environment]::NewLine).Trim()
    }
    if ($output) {
        $output | ForEach-Object { Write-Verbose $_ }
    }
}

function Invoke-OpenSslExpectedFailure {
    param(
        [Parameter(Mandatory = $true)][string[]] $Arguments,
        [Parameter(Mandatory = $true)][string] $Description
    )
    $output = & $script:OpenSslExecutable @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    if ($exitCode -eq 0) {
        throw "Expected OpenSSL to fail while $Description, but it succeeded."
    }
    return ($output -join [Environment]::NewLine).Trim()
}

function Enter-CaOperationLock {
    param([Parameter(Mandatory = $true)][string] $BasePath)

    $databaseDirectory = Join-Path $BasePath 'db'
    [System.IO.Directory]::CreateDirectory($databaseDirectory) | Out-Null
    $lockPath = Join-Path $databaseDirectory 'ca-operation.lock'
    try {
        $stream = [System.IO.File]::Open(
            $lockPath,
            [System.IO.FileMode]::OpenOrCreate,
            [System.IO.FileAccess]::ReadWrite,
            [System.IO.FileShare]::None
        )
    }
    catch {
        throw "Another CA operation is already active for '$BasePath', or the CA database lock cannot be acquired. Do not run concurrent OpenSSL CA operations. $($_.Exception.Message)"
    }

    try {
        $stream.SetLength(0)
        $writer = [System.IO.StreamWriter]::new($stream, $script:Utf8NoBom, 1024, $true)
        try {
            $writer.WriteLine("processId=$PID")
            $writer.WriteLine("machine=$([Environment]::MachineName)")
            $writer.WriteLine("user=$([Environment]::UserName)")
            $writer.WriteLine("acquiredUtc=$([DateTime]::UtcNow.ToString('o'))")
            $writer.Flush()
            $stream.Flush($true)
        }
        finally {
            $writer.Dispose()
        }
        return $stream
    }
    catch {
        $stream.Dispose()
        throw
    }
}

function Exit-CaOperationLock {
    param(
        [AllowNull()][System.IO.FileStream] $LockHandle,
        [Parameter(Mandatory = $true)][string] $BasePath
    )
    if ($null -ne $LockHandle) {
        $LockHandle.Dispose()
    }
    $lockPath = Join-Path $BasePath 'db\ca-operation.lock'
    Remove-Item -LiteralPath $lockPath -Force -ErrorAction SilentlyContinue
}

function Backup-CaDatabase {
    param([Parameter(Mandatory = $true)][string] $BasePath)

    $backupRoot = Join-Path $BasePath 'db\backups'
    $backupDirectory = Join-Path $backupRoot ((Get-Date -Format 'yyyyMMddTHHmmssffff') + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
    [System.IO.Directory]::CreateDirectory($backupDirectory) | Out-Null
    foreach ($relativePath in @('index.txt', 'index.txt.attr', 'serial', 'crlnumber')) {
        $source = Join-Path (Join-Path $BasePath 'db') $relativePath
        if (Test-Path -LiteralPath $source -PathType Leaf) {
            Copy-Item -LiteralPath $source -Destination (Join-Path $backupDirectory $relativePath) -Force
        }
    }
    return $backupDirectory
}

function Invoke-OpenSslCa {
    param(
        [Parameter(Mandatory = $true)][string] $BasePath,
        [Parameter(Mandatory = $true)][string[]] $Arguments,
        [Parameter(Mandatory = $true)][string] $Description
    )

    $lockHandle = $null
    try {
        $lockHandle = Enter-CaOperationLock -BasePath $BasePath
        [void] (Backup-CaDatabase -BasePath $BasePath)
        Invoke-OpenSsl -Arguments $Arguments -Description $Description
    }
    finally {
        Exit-CaOperationLock -LockHandle $lockHandle -BasePath $BasePath
    }
}

function New-CaDirectoryLayout {
    param([Parameter(Mandatory = $true)][string] $BasePath)
    if (Test-Path -LiteralPath $BasePath) {
        $existing = Get-ChildItem -LiteralPath $BasePath -Force -ErrorAction SilentlyContinue
        if ($existing.Count -gt 0) {
            throw "Refusing to initialize a non-empty CA directory: $BasePath"
        }
    }
    [System.IO.Directory]::CreateDirectory($BasePath) | Out-Null
    Set-RestrictedAcl -Path $BasePath -Directory -IncludeAdministrators
    foreach ($name in @('certs', 'crl', 'csr', 'db', 'newcerts', 'private', 'publish', 'logs')) {
        [System.IO.Directory]::CreateDirectory((Join-Path $BasePath $name)) | Out-Null
    }
    Set-RestrictedAcl -Path (Join-Path $BasePath 'private') -Directory -IncludeAdministrators
}

function Initialize-CaDatabase {
    param([Parameter(Mandatory = $true)][string] $BasePath)
    Write-AsciiFile -Path (Join-Path $BasePath 'db\index.txt') -Content ''
    Write-AsciiFile -Path (Join-Path $BasePath 'db\index.txt.attr') -Content "unique_subject = no`n"
    Write-AsciiFile -Path (Join-Path $BasePath 'db\serial') -Content ((New-RandomHex -Bytes 16) + "`n")
    Write-AsciiFile -Path (Join-Path $BasePath 'db\crlnumber') -Content "1000`n"
}

function Get-DistinguishedNameLines {
    param(
        [Parameter(Mandatory = $true)][string] $CountryCode,
        [AllowEmptyString()][string] $Province,
        [AllowEmptyString()][string] $City,
        [Parameter(Mandatory = $true)][string] $Org,
        [AllowEmptyString()][string] $OrgUnit,
        [Parameter(Mandatory = $true)][string] $CommonName,
        [AllowEmptyString()][string] $Title,
        [AllowEmptyString()][string] $Email
    )
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('C = ' + (Quote-OpenSslConfigValue -Value $CountryCode.ToUpperInvariant()))
    if (-not [string]::IsNullOrWhiteSpace($Province)) {
        $lines.Add('ST = ' + (Quote-OpenSslConfigValue -Value $Province))
    }
    if (-not [string]::IsNullOrWhiteSpace($City)) {
        $lines.Add('L = ' + (Quote-OpenSslConfigValue -Value $City))
    }
    $lines.Add('O = ' + (Quote-OpenSslConfigValue -Value $Org))
    if (-not [string]::IsNullOrWhiteSpace($OrgUnit)) {
        $lines.Add('OU = ' + (Quote-OpenSslConfigValue -Value $OrgUnit))
    }
    if (-not [string]::IsNullOrWhiteSpace($Title)) {
        $lines.Add('title = ' + (Quote-OpenSslConfigValue -Value $Title))
    }
    $lines.Add('CN = ' + (Quote-OpenSslConfigValue -Value $CommonName))
    if (-not [string]::IsNullOrWhiteSpace($Email)) {
        $lines.Add('emailAddress = ' + (Quote-OpenSslConfigValue -Value $Email))
    }
    return ($lines -join [Environment]::NewLine)
}

function New-RootOpenSslConfig {
    param(
        [Parameter(Mandatory = $true)][string] $BasePath,
        [Parameter(Mandatory = $true)][pscustomobject] $Metadata
    )
    $base = ConvertTo-OpenSslPath -Path $BasePath
    $rootCertUrl = "$($Metadata.pkiBaseUrl)/root-ca.cer"
    $rootCrlUrl = "$($Metadata.pkiBaseUrl)/root-ca.crl"
    $dn = Get-DistinguishedNameLines `
        -CountryCode $Metadata.country `
        -Province $Metadata.stateOrProvince `
        -City $Metadata.locality `
        -Org $Metadata.organization `
        -OrgUnit $Metadata.rootOrganizationalUnit `
        -CommonName $Metadata.rootCommonName `
        -Title '' `
        -Email ''

    $content = @"
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = "$base"
certs             = "$base/certs"
crl_dir           = "$base/crl"
new_certs_dir     = "$base/newcerts"
database          = "$base/db/index.txt"
serial            = "$base/db/serial"
crlnumber         = "$base/db/crlnumber"
certificate       = "$base/certs/root-ca.cert.pem"
private_key       = "$base/private/root-ca.key.pem"
crl               = "$base/crl/root-ca.crl.pem"
default_md        = sha384
default_days      = $($Metadata.issuingValidityDays)
default_crl_days  = $($Metadata.rootCrlDays)
policy            = policy_strict
email_in_dn       = no
preserve          = no
copy_extensions   = none
unique_subject    = no
name_opt          = ca_default
cert_opt          = ca_default
crl_extensions    = crl_ext

[ policy_strict ]
countryName             = match
stateOrProvinceName     = optional
localityName            = optional
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits        = 4096
prompt              = no
distinguished_name  = root_dn
x509_extensions     = v3_root_ca
string_mask         = utf8only
utf8                = yes

[ root_dn ]
$dn

[ v3_root_ca ]
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always
basicConstraints        = critical, CA:true, pathlen:1
keyUsage                = critical, keyCertSign, cRLSign

[ v3_intermediate_ca ]
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always, issuer
basicConstraints        = critical, CA:true, pathlen:0
keyUsage                = critical, keyCertSign, cRLSign
authorityInfoAccess     = caIssuers;URI:$rootCertUrl
crlDistributionPoints   = URI:$rootCrlUrl

[ crl_ext ]
authorityKeyIdentifier  = keyid:always
"@
    Write-Utf8File -Path (Join-Path $BasePath 'openssl-root.cnf') -Content $content
}

function New-IssuingRequestConfig {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][pscustomobject] $Metadata
    )
    $dn = Get-DistinguishedNameLines `
        -CountryCode $Metadata.country `
        -Province $Metadata.stateOrProvince `
        -City $Metadata.locality `
        -Org $Metadata.organization `
        -OrgUnit $Metadata.issuingOrganizationalUnit `
        -CommonName $Metadata.issuingCommonName `
        -Title '' `
        -Email ''

    $content = @"
[ req ]
default_bits        = 4096
prompt              = no
distinguished_name  = issuing_dn
string_mask         = utf8only
utf8                = yes

[ issuing_dn ]
$dn
"@
    Write-Utf8File -Path $Path -Content $content
}

function New-IssuingOpenSslConfig {
    param(
        [Parameter(Mandatory = $true)][string] $BasePath,
        [Parameter(Mandatory = $true)][pscustomobject] $Metadata
    )
    $base = ConvertTo-OpenSslPath -Path $BasePath
    $content = @"
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = "$base"
certs             = "$base/certs"
crl_dir           = "$base/crl"
new_certs_dir     = "$base/newcerts"
database          = "$base/db/index.txt"
serial            = "$base/db/serial"
crlnumber         = "$base/db/crlnumber"
certificate       = "$base/certs/issuing-ca.cert.pem"
private_key       = "$base/private/issuing-ca.key.pem"
crl               = "$base/crl/issuing-ca.crl.pem"
default_md        = sha256
default_days      = $($Metadata.signerValidityDays)
default_crl_days  = $($Metadata.issuingCrlDays)
policy            = policy_loose
email_in_dn       = no
preserve          = no
copy_extensions   = none
unique_subject    = no
name_opt          = ca_default
cert_opt          = ca_default
crl_extensions    = crl_ext

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
title                   = optional
commonName              = supplied
emailAddress            = optional

[ crl_ext ]
authorityKeyIdentifier  = keyid:always
"@
    Write-Utf8File -Path (Join-Path $BasePath 'openssl-issuing.cnf') -Content $content
}

function New-SignerRequestConfig {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][pscustomobject] $Subject
    )
    $dn = Get-DistinguishedNameLines `
        -CountryCode $Subject.country `
        -Province $Subject.stateOrProvince `
        -City $Subject.locality `
        -Org $Subject.organization `
        -OrgUnit $Subject.organizationalUnit `
        -CommonName $Subject.commonName `
        -Title $Subject.title `
        -Email $Subject.email

    $content = @"
[ req ]
default_bits        = 3072
prompt              = no
distinguished_name  = signer_dn
string_mask         = utf8only
utf8                = yes

[ signer_dn ]
$dn
"@
    Write-Utf8File -Path $Path -Content $content
}

function New-SignerExtensionConfig {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][pscustomobject] $Metadata,
        [Parameter(Mandatory = $true)][string] $Email
    )
    Assert-NoNewLine -Name 'SignerEmail' -Value $Email
    if ($Email -match '\s') {
        throw 'SignerEmail must not contain whitespace.'
    }
    $emailConfigValue = Quote-OpenSslConfigValue -Value $Email
    $issuingCertUrl = "$($Metadata.pkiBaseUrl)/issuing-ca.cer"
    $issuingCrlUrl = "$($Metadata.pkiBaseUrl)/issuing-ca.crl"
    $aia = "caIssuers;URI:$issuingCertUrl"
    if (-not [string]::IsNullOrWhiteSpace([string] $Metadata.ocspUrl)) {
        Test-AbsoluteHttpUrl -Name 'OcspUrl' -Value ([string] $Metadata.ocspUrl)
        $aia = $aia + ", OCSP;URI:$($Metadata.ocspUrl)"
    }

    $content = @"
[ document_signer ]
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always, issuer
basicConstraints        = critical, CA:false
keyUsage                = critical, digitalSignature, nonRepudiation
extendedKeyUsage        = 1.3.6.1.5.5.7.3.36, 1.3.6.1.4.1.311.10.3.12, 1.2.840.113583.1.1.5
subjectAltName          = @signer_alt_names
authorityInfoAccess     = $aia
crlDistributionPoints   = URI:$issuingCrlUrl

[ signer_alt_names ]
email.1 = $emailConfigValue
"@
    Write-Utf8File -Path $Path -Content $content
}

function Save-Json {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)] $Object
    )
    $json = $Object | ConvertTo-Json -Depth 10
    Write-Utf8File -Path $Path -Content ($json + [Environment]::NewLine)
}

function Read-Json {
    param([Parameter(Mandatory = $true)][string] $Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required metadata file was not found: $Path"
    }
    return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json)
}

function Write-AuditEvent {
    param(
        [Parameter(Mandatory = $true)][string] $BasePath,
        [Parameter(Mandatory = $true)][string] $EventAction,
        [Parameter(Mandatory = $true)][hashtable] $Details
    )
    $logDirectory = Join-Path $BasePath 'logs'
    [System.IO.Directory]::CreateDirectory($logDirectory) | Out-Null
    $record = [ordered]@{
        schemaVersion = 1
        eventId       = [Guid]::NewGuid().ToString()
        occurredUtc   = [DateTime]::UtcNow.ToString('o')
        action        = $EventAction
        actor         = [Environment]::UserName
        machine       = [Environment]::MachineName
        openssl       = $script:OpenSslVersion
        details       = $Details
    }
    $line = ($record | ConvertTo-Json -Depth 10 -Compress) + [Environment]::NewLine
    $path = Join-Path $logDirectory 'operations.jsonl'
    [System.IO.File]::AppendAllText($path, $line, $script:Utf8NoBom)
}

function Copy-FileAtomic {
    param(
        [Parameter(Mandatory = $true)][string] $Source,
        [Parameter(Mandatory = $true)][string] $Destination
    )
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
        throw "Source file not found: $Source"
    }
    $destinationDirectory = Split-Path -Parent $Destination
    [System.IO.Directory]::CreateDirectory($destinationDirectory) | Out-Null
    $temporary = Join-Path $destinationDirectory ('.' + [System.IO.Path]::GetFileName($Destination) + '.' + [Guid]::NewGuid().ToString('N') + '.tmp')
    Copy-Item -LiteralPath $Source -Destination $temporary -Force
    Move-Item -LiteralPath $temporary -Destination $Destination -Force
}

function Join-PemFiles {
    param(
        [Parameter(Mandatory = $true)][string[]] $InputFiles,
        [Parameter(Mandatory = $true)][string] $OutputFile
    )
    $builder = New-Object System.Text.StringBuilder
    foreach ($file in $InputFiles) {
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
            throw "PEM input file not found: $file"
        }
        [void] $builder.Append((Get-Content -LiteralPath $file -Raw).Trim())
        [void] $builder.Append([Environment]::NewLine)
    }
    Write-Utf8File -Path $OutputFile -Content $builder.ToString()
}

function Write-ChecksumManifest {
    param(
        [Parameter(Mandatory = $true)][string] $Directory,
        [Parameter(Mandatory = $true)][string[]] $RelativeFiles
    )
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($relative in $RelativeFiles) {
        $full = Join-Path $Directory $relative
        if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
            throw "Cannot hash missing bundle file: $full"
        }
        $hash = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToLowerInvariant()
        $lines.Add("$hash  $relative")
    }
    Write-AsciiFile -Path (Join-Path $Directory 'SHA256SUMS.txt') -Content (($lines -join [Environment]::NewLine) + [Environment]::NewLine)
}

function Test-ChecksumManifest {
    param(
        [Parameter(Mandatory = $true)][string] $Directory,
        [string[]] $RequiredRelativeFiles = @()
    )
    $manifest = Join-Path $Directory 'SHA256SUMS.txt'
    if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) {
        throw "Bundle checksum manifest is missing: $manifest"
    }

    $baseDirectory = [System.IO.Path]::GetFullPath($Directory)
    $basePrefix = $baseDirectory.TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    ) + [System.IO.Path]::DirectorySeparatorChar
    $seenFiles = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($line in Get-Content -LiteralPath $manifest) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }
        if ($line -notmatch '^(?<hash>[0-9a-fA-F]{64})\s{2}(?<file>.+)$') {
            throw "Invalid checksum manifest line: $line"
        }
        $expectedHash = $Matches.hash.ToUpperInvariant()
        $relativeFile = $Matches.file
        if ([System.IO.Path]::IsPathRooted($relativeFile)) {
            throw "Checksum manifest entries must be relative paths: $relativeFile"
        }

        $canonicalRelativeFile = $relativeFile.Replace('\', '/')
        if (-not $seenFiles.Add($canonicalRelativeFile)) {
            throw "Duplicate checksum manifest entry: $relativeFile"
        }

        $full = [System.IO.Path]::GetFullPath((Join-Path $Directory $relativeFile))
        if (-not $full.StartsWith($basePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Checksum manifest entry escapes the bundle directory: $relativeFile"
        }
        if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
            throw "Bundle file listed in checksum manifest is missing: $relativeFile"
        }
        $actual = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash
        if ($actual -cne $expectedHash) {
            throw "Checksum mismatch for bundle file: $relativeFile"
        }
    }

    foreach ($requiredRelativeFile in $RequiredRelativeFiles) {
        $canonicalRequiredFile = $requiredRelativeFile.Replace('\', '/')
        if (-not $seenFiles.Contains($canonicalRequiredFile)) {
            throw "Required bundle file is not protected by the checksum manifest: $requiredRelativeFile"
        }
    }
}

function Get-CertificateProperty {
    param(
        [Parameter(Mandatory = $true)][string] $Certificate,
        [Parameter(Mandatory = $true)][ValidateSet('fingerprint', 'serial', 'subject', 'issuer', 'dates')][string] $Property
    )
    switch ($Property) {
        'fingerprint' {
            $output = Invoke-OpenSsl -Arguments @('x509', '-in', $Certificate, '-noout', '-fingerprint', '-sha256') -Description 'reading certificate fingerprint' -PassThru
        }
        'serial' {
            $output = Invoke-OpenSsl -Arguments @('x509', '-in', $Certificate, '-noout', '-serial') -Description 'reading certificate serial number' -PassThru
        }
        'subject' {
            $output = Invoke-OpenSsl -Arguments @('x509', '-in', $Certificate, '-noout', '-subject', '-nameopt', 'RFC2253') -Description 'reading certificate subject' -PassThru
        }
        'issuer' {
            $output = Invoke-OpenSsl -Arguments @('x509', '-in', $Certificate, '-noout', '-issuer', '-nameopt', 'RFC2253') -Description 'reading certificate issuer' -PassThru
        }
        'dates' {
            $output = Invoke-OpenSsl -Arguments @('x509', '-in', $Certificate, '-noout', '-dates') -Description 'reading certificate dates' -PassThru
        }
    }
    return $output
}

function Normalize-Sha256Fingerprint {
    param(
        [Parameter(Mandatory = $true)][string] $Value,
        [string] $Name = 'SHA-256 fingerprint'
    )
    $normalized = $Value.Trim()
    $normalized = [System.Text.RegularExpressions.Regex]::Replace(
        $normalized,
        '^sha256\s+fingerprint\s*=\s*',
        '',
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )
    $normalized = [System.Text.RegularExpressions.Regex]::Replace($normalized, '[^0-9A-Fa-f]', '')
    if ($normalized -notmatch '^[0-9A-Fa-f]{64}$') {
        throw "$Name must contain exactly 32 SHA-256 bytes, supplied as 64 hexadecimal characters with or without colon separators."
    }
    return $normalized.ToUpperInvariant()
}

function Get-NormalizedCertificateFingerprint {
    param([Parameter(Mandatory = $true)][string] $Certificate)
    $fingerprint = Get-CertificateProperty -Certificate $Certificate -Property fingerprint
    return Normalize-Sha256Fingerprint -Value $fingerprint -Name "Certificate fingerprint for '$Certificate'"
}

function Test-CsrMatchesCertificate {
    param(
        [Parameter(Mandatory = $true)][string] $Csr,
        [Parameter(Mandatory = $true)][string] $Certificate
    )
    $tempDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ('pki-csrmatch-' + [Guid]::NewGuid().ToString('N'))
    [System.IO.Directory]::CreateDirectory($tempDirectory) | Out-Null
    try {
        $csrPublicPem = Join-Path $tempDirectory 'csr-public.pem'
        $certPublicPem = Join-Path $tempDirectory 'cert-public.pem'
        $csrPublicDer = Join-Path $tempDirectory 'csr-public.der'
        $certPublicDer = Join-Path $tempDirectory 'cert-public.der'

        Invoke-OpenSsl -Arguments @('req', '-in', $Csr, '-pubkey', '-noout', '-out', $csrPublicPem) -Description 'extracting public key from CSR'
        Invoke-OpenSsl -Arguments @('x509', '-in', $Certificate, '-pubkey', '-noout', '-out', $certPublicPem) -Description 'extracting public key from certificate'
        Invoke-OpenSsl -Arguments @('pkey', '-pubin', '-in', $csrPublicPem, '-outform', 'DER', '-out', $csrPublicDer) -Description 'normalizing CSR public key'
        Invoke-OpenSsl -Arguments @('pkey', '-pubin', '-in', $certPublicPem, '-outform', 'DER', '-out', $certPublicDer) -Description 'normalizing certificate public key'

        $csrHash = (Get-FileHash -LiteralPath $csrPublicDer -Algorithm SHA256).Hash
        $certHash = (Get-FileHash -LiteralPath $certPublicDer -Algorithm SHA256).Hash
        if ($csrHash -cne $certHash) {
            throw 'The signed certificate public key does not match the Issuing CA CSR public key.'
        }
    }
    finally {
        if (Test-Path -LiteralPath $tempDirectory) {
            Remove-Item -LiteralPath $tempDirectory -Recurse -Force
        }
    }
}

function Assert-PropertyEqual {
    param(
        [Parameter(Mandatory = $true)] $ExpectedObject,
        [Parameter(Mandatory = $true)] $ActualObject,
        [Parameter(Mandatory = $true)][string] $PropertyName,
        [string] $Context = 'metadata'
    )
    $expectedProperty = $ExpectedObject.PSObject.Properties[$PropertyName]
    $actualProperty = $ActualObject.PSObject.Properties[$PropertyName]
    if ($null -eq $expectedProperty -or $null -eq $actualProperty) {
        throw "$Context is missing required property '$PropertyName'."
    }
    $expectedValue = [string] $expectedProperty.Value
    $actualValue = [string] $actualProperty.Value
    if ($expectedValue -cne $actualValue) {
        throw "$Context mismatch for '$PropertyName'. Expected '$expectedValue'; received '$actualValue'."
    }
}

function Test-CertificateCanOutlive {
    param(
        [Parameter(Mandatory = $true)][string] $IssuerCertificate,
        [Parameter(Mandatory = $true)][int] $RequestedDays
    )
    $seconds = [int64] $RequestedDays * 86400L
    $output = & $script:OpenSslExecutable x509 -in $IssuerCertificate -noout -checkend $seconds 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Issuer certificate does not remain valid for the requested $RequestedDays-day certificate lifetime. Renew the issuer or reduce the requested validity period.`n$($output -join [Environment]::NewLine)"
    }
}

function Test-KeyMatchesCertificate {
    param(
        [Parameter(Mandatory = $true)][string] $PrivateKey,
        [Parameter(Mandatory = $true)][string] $Certificate,
        [Parameter(Mandatory = $true)][string] $PasswordSource
    )
    $tempDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ('pki-keymatch-' + [Guid]::NewGuid().ToString('N'))
    [System.IO.Directory]::CreateDirectory($tempDirectory) | Out-Null
    try {
        $keyPublicPem = Join-Path $tempDirectory 'key-public.pem'
        $certPublicPem = Join-Path $tempDirectory 'cert-public.pem'
        $keyPublicDer = Join-Path $tempDirectory 'key-public.der'
        $certPublicDer = Join-Path $tempDirectory 'cert-public.der'

        Invoke-OpenSsl -Arguments @('pkey', '-in', $PrivateKey, '-passin', $PasswordSource, '-pubout', '-out', $keyPublicPem) -Description 'extracting public key from private key'
        Invoke-OpenSsl -Arguments @('x509', '-in', $Certificate, '-pubkey', '-noout', '-out', $certPublicPem) -Description 'extracting public key from certificate'
        Invoke-OpenSsl -Arguments @('pkey', '-pubin', '-in', $keyPublicPem, '-outform', 'DER', '-out', $keyPublicDer) -Description 'normalizing private-key public key'
        Invoke-OpenSsl -Arguments @('pkey', '-pubin', '-in', $certPublicPem, '-outform', 'DER', '-out', $certPublicDer) -Description 'normalizing certificate public key'

        $keyHash = (Get-FileHash -LiteralPath $keyPublicDer -Algorithm SHA256).Hash
        $certHash = (Get-FileHash -LiteralPath $certPublicDer -Algorithm SHA256).Hash
        if ($keyHash -cne $certHash) {
            throw 'The private key does not match the certificate public key.'
        }
    }
    finally {
        if (Test-Path -LiteralPath $tempDirectory) {
            Remove-Item -LiteralPath $tempDirectory -Recurse -Force
        }
    }
}

function Publish-RootArtifacts {
    param([Parameter(Mandatory = $true)][string] $BasePath)
    $publish = Join-Path $BasePath 'publish'
    Copy-FileAtomic -Source (Join-Path $BasePath 'certs\root-ca.cert.der') -Destination (Join-Path $publish 'root-ca.cer')
    Copy-FileAtomic -Source (Join-Path $BasePath 'certs\root-ca.cert.pem') -Destination (Join-Path $publish 'root-ca.pem')
    Copy-FileAtomic -Source (Join-Path $BasePath 'crl\root-ca.crl.der') -Destination (Join-Path $publish 'root-ca.crl')
    Copy-FileAtomic -Source (Join-Path $BasePath 'crl\root-ca.crl.pem') -Destination (Join-Path $publish 'root-ca-crl.pem')
}

function Publish-IssuingArtifacts {
    param([Parameter(Mandatory = $true)][string] $BasePath)
    $publish = Join-Path $BasePath 'publish'
    Copy-FileAtomic -Source (Join-Path $BasePath 'certs\root-ca.cert.der') -Destination (Join-Path $publish 'root-ca.cer')
    Copy-FileAtomic -Source (Join-Path $BasePath 'certs\root-ca.cert.pem') -Destination (Join-Path $publish 'root-ca.pem')
    if (Test-Path -LiteralPath (Join-Path $BasePath 'crl\root-ca.crl.der')) {
        Copy-FileAtomic -Source (Join-Path $BasePath 'crl\root-ca.crl.der') -Destination (Join-Path $publish 'root-ca.crl')
    }
    if (Test-Path -LiteralPath (Join-Path $BasePath 'crl\root-ca.crl.pem')) {
        Copy-FileAtomic -Source (Join-Path $BasePath 'crl\root-ca.crl.pem') -Destination (Join-Path $publish 'root-ca-crl.pem')
    }
    Copy-FileAtomic -Source (Join-Path $BasePath 'certs\issuing-ca.cert.der') -Destination (Join-Path $publish 'issuing-ca.cer')
    Copy-FileAtomic -Source (Join-Path $BasePath 'certs\issuing-ca.cert.pem') -Destination (Join-Path $publish 'issuing-ca.pem')
    Copy-FileAtomic -Source (Join-Path $BasePath 'crl\issuing-ca.crl.der') -Destination (Join-Path $publish 'issuing-ca.crl')
    Copy-FileAtomic -Source (Join-Path $BasePath 'crl\issuing-ca.crl.pem') -Destination (Join-Path $publish 'issuing-ca-crl.pem')
}

function New-Crl {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Root', 'Issuing')][string] $CaType,
        [Parameter(Mandatory = $true)][string] $BasePath,
        [Parameter(Mandatory = $true)][string] $PasswordSource
    )
    if ($CaType -eq 'Root') {
        $config = Join-Path $BasePath 'openssl-root.cnf'
        $pem = Join-Path $BasePath 'crl\root-ca.crl.pem'
        $der = Join-Path $BasePath 'crl\root-ca.crl.der'
    }
    else {
        $config = Join-Path $BasePath 'openssl-issuing.cnf'
        $pem = Join-Path $BasePath 'crl\issuing-ca.crl.pem'
        $der = Join-Path $BasePath 'crl\issuing-ca.crl.der'
    }

    $tempPem = $pem + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    $tempDer = $der + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    try {
        Invoke-OpenSslCa -BasePath $BasePath -Arguments @('ca', '-config', $config, '-gencrl', '-out', $tempPem, '-passin', $PasswordSource) -Description "generating $CaType CA CRL"
        Invoke-OpenSsl -Arguments @('crl', '-in', $tempPem, '-outform', 'DER', '-out', $tempDer) -Description "converting $CaType CA CRL to DER"
        Invoke-OpenSsl -Arguments @('crl', '-in', $tempPem, '-noout', '-issuer', '-lastupdate', '-nextupdate', '-crlnumber') -Description "validating $CaType CA CRL"
        Move-Item -LiteralPath $tempPem -Destination $pem -Force
        Move-Item -LiteralPath $tempDer -Destination $der -Force
    }
    finally {
        Remove-Item -LiteralPath $tempPem -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $tempDer -Force -ErrorAction SilentlyContinue
    }

    if ($CaType -eq 'Root') {
        Publish-RootArtifacts -BasePath $BasePath
    }
    else {
        Publish-IssuingArtifacts -BasePath $BasePath
    }
}

function Verify-SignerCertificateChain {
    param(
        [Parameter(Mandatory = $true)][string] $IssuingPath,
        [Parameter(Mandatory = $true)][string] $SignerCertificate
    )
    $rootCert = Join-Path $IssuingPath 'certs\root-ca.cert.pem'
    $issuingCert = Join-Path $IssuingPath 'certs\issuing-ca.cert.pem'
    $rootCrl = Join-Path $IssuingPath 'crl\root-ca.crl.pem'
    $issuingCrl = Join-Path $IssuingPath 'crl\issuing-ca.crl.pem'

    Invoke-OpenSsl -Arguments @('verify', '-x509_strict', '-show_chain', '-CAfile', $rootCert, '-untrusted', $issuingCert, $SignerCertificate) -Description 'verifying document signer certificate chain'

    if ((Test-Path -LiteralPath $rootCrl) -and (Test-Path -LiteralPath $issuingCrl)) {
        $combinedCrl = Join-Path ([System.IO.Path]::GetTempPath()) ('combined-' + [Guid]::NewGuid().ToString('N') + '.crl.pem')
        try {
            Join-PemFiles -InputFiles @($issuingCrl, $rootCrl) -OutputFile $combinedCrl
            Invoke-OpenSsl -Arguments @('verify', '-x509_strict', '-CAfile', $rootCert, '-untrusted', $issuingCert, '-CRLfile', $combinedCrl, '-crl_check_all', $SignerCertificate) -Description 'verifying document signer certificate with CRLs'
        }
        finally {
            Remove-Item -LiteralPath $combinedCrl -Force -ErrorAction SilentlyContinue
        }
    }
    else {
        Write-Warning 'One or more CRL files are unavailable; cryptographic chain verification succeeded, but CRL verification was skipped.'
    }
}

function Invoke-InitializeRoot {
    Assert-RequiredValue -Name 'Organization' -Value $Organization
    Assert-RequiredValue -Name 'PkiBaseUrl' -Value $PkiBaseUrl
    $normalizedBaseUrl = Normalize-PkiBaseUrl -Value $PkiBaseUrl
    if (-not [string]::IsNullOrWhiteSpace($OcspUrl)) {
        Test-AbsoluteHttpUrl -Name 'OcspUrl' -Value $OcspUrl
    }

    $year = (Get-Date).Year
    $rootCn = if ([string]::IsNullOrWhiteSpace($RootCommonName)) { "$Organization Root CA $year" } else { $RootCommonName }
    foreach ($entry in @{
        Organization = $Organization; StateOrProvince = $StateOrProvince; Locality = $Locality;
        RootOrganizationalUnit = $RootOrganizationalUnit; RootCommonName = $rootCn
    }.GetEnumerator()) {
        Assert-NoNewLine -Name $entry.Key -Value ([string] $entry.Value)
    }

    Write-Section 'INITIALIZE OFFLINE ROOT CA'
    if (-not $PSCmdlet.ShouldProcess($RootCaPath, 'Create encrypted Root CA private key, self-signed Root CA certificate, database, and initial CRL')) {
        return
    }

    New-CaDirectoryLayout -BasePath $RootCaPath
    Initialize-CaDatabase -BasePath $RootCaPath

    $metadata = [pscustomobject][ordered]@{
        schemaVersion             = 1
        caType                    = 'RootCA'
        createdUtc                = [DateTime]::UtcNow.ToString('o')
        pkiBaseUrl                = $normalizedBaseUrl
        ocspUrl                   = $OcspUrl
        country                   = $Country.ToUpperInvariant()
        stateOrProvince           = $StateOrProvince
        locality                  = $Locality
        organization              = $Organization
        rootOrganizationalUnit    = $RootOrganizationalUnit
        rootCommonName            = $rootCn
        rootValidityDays          = $RootValidityDays
        issuingValidityDays       = $IssuingValidityDays
        signerValidityDays        = $SignerValidityDays
        rootCrlDays               = $RootCrlDays
        issuingCrlDays            = $IssuingCrlDays
        rootCertificateUrl        = "$normalizedBaseUrl/root-ca.cer"
        rootCrlUrl                = "$normalizedBaseUrl/root-ca.crl"
        issuingCertificateUrl     = "$normalizedBaseUrl/issuing-ca.cer"
        issuingCrlUrl             = "$normalizedBaseUrl/issuing-ca.crl"
        openssl                   = $script:OpenSslVersion
    }
    Save-Json -Path (Join-Path $RootCaPath 'pki-metadata.json') -Object $metadata
    New-RootOpenSslConfig -BasePath $RootCaPath -Metadata $metadata

    $rootPassword = Read-ValidatedPassphrase -Prompt 'Enter a new Root CA private-key passphrase (store it offline in an approved password vault)'
    $secretFile = New-TemporarySecretFile -Secret $rootPassword -Label 'root-ca'
    $passwordSource = Get-OpenSslPasswordSource -SecretFilePath $secretFile
    try {
        $rootKey = Join-Path $RootCaPath 'private\root-ca.key.pem'
        $rootCert = Join-Path $RootCaPath 'certs\root-ca.cert.pem'
        $rootCertDer = Join-Path $RootCaPath 'certs\root-ca.cert.der'
        $rootConfig = Join-Path $RootCaPath 'openssl-root.cnf'
        $serial = '0x' + (New-RandomHex -Bytes 16)

        Invoke-OpenSsl -Arguments @('genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:4096', '-aes-256-cbc', '-pass', $passwordSource, '-out', $rootKey) -Description 'generating Root CA private key'
        Set-RestrictedAcl -Path $rootKey -IncludeAdministrators
        Invoke-OpenSsl -Arguments @('pkey', '-in', $rootKey, '-passin', $passwordSource, '-check', '-noout') -Description 'checking Root CA private key'
        Invoke-OpenSsl -Arguments @('req', '-config', $rootConfig, '-key', $rootKey, '-passin', $passwordSource, '-new', '-x509', '-days', [string] $RootValidityDays, '-sha384', '-set_serial', $serial, '-extensions', 'v3_root_ca', '-out', $rootCert) -Description 'creating self-signed Root CA certificate'
        Invoke-OpenSsl -Arguments @('x509', '-in', $rootCert, '-outform', 'DER', '-out', $rootCertDer) -Description 'converting Root CA certificate to DER'
        Invoke-OpenSsl -Arguments @('verify', '-x509_strict', '-check_ss_sig', '-CAfile', $rootCert, $rootCert) -Description 'verifying Root CA certificate'
        New-Crl -CaType Root -BasePath $RootCaPath -PasswordSource $passwordSource

        $fingerprint = Get-CertificateProperty -Certificate $rootCert -Property fingerprint
        Write-AuditEvent -BasePath $RootCaPath -EventAction 'RootCaInitialized' -Details @{
            certificate = $rootCert
            fingerprint = $fingerprint
            pkiBaseUrl   = $normalizedBaseUrl
        }

        Write-Host "Root CA created: $rootCert"
        Write-Host "Root CA SHA-256 fingerprint: $fingerprint"
        Write-Host "Public artifacts: $(Join-Path $RootCaPath 'publish')"
        Write-Warning 'Disconnect and retain the Root CA computer offline. Do not copy root-ca.key.pem to the Issuing CA computer.'
    }
    finally {
        Remove-TemporarySecretFile -Path $secretFile
    }
}

function Invoke-CreateIssuingRequest {
    Assert-RequiredValue -Name 'Organization' -Value $Organization
    Assert-RequiredValue -Name 'PkiBaseUrl' -Value $PkiBaseUrl
    $normalizedBaseUrl = Normalize-PkiBaseUrl -Value $PkiBaseUrl
    if (-not [string]::IsNullOrWhiteSpace($OcspUrl)) {
        Test-AbsoluteHttpUrl -Name 'OcspUrl' -Value $OcspUrl
    }

    $year = (Get-Date).Year
    $issuingCn = if ([string]::IsNullOrWhiteSpace($IssuingCommonName)) { "$Organization Document Signing Issuing CA $year" } else { $IssuingCommonName }
    foreach ($entry in @{
        Organization = $Organization; StateOrProvince = $StateOrProvince; Locality = $Locality;
        IssuingOrganizationalUnit = $IssuingOrganizationalUnit; IssuingCommonName = $issuingCn
    }.GetEnumerator()) {
        Assert-NoNewLine -Name $entry.Key -Value ([string] $entry.Value)
    }

    Write-Section 'CREATE ISSUING CA PRIVATE KEY AND CSR'
    if (-not $PSCmdlet.ShouldProcess($IssuingCaPath, 'Create encrypted Issuing CA private key and CSR')) {
        return
    }

    New-CaDirectoryLayout -BasePath $IssuingCaPath
    Initialize-CaDatabase -BasePath $IssuingCaPath
    [System.IO.Directory]::CreateDirectory($TransferPath) | Out-Null

    $metadata = [pscustomobject][ordered]@{
        schemaVersion              = 1
        caType                     = 'IssuingCARequest'
        createdUtc                 = [DateTime]::UtcNow.ToString('o')
        pkiBaseUrl                 = $normalizedBaseUrl
        ocspUrl                    = $OcspUrl
        country                    = $Country.ToUpperInvariant()
        stateOrProvince            = $StateOrProvince
        locality                   = $Locality
        organization               = $Organization
        issuingOrganizationalUnit  = $IssuingOrganizationalUnit
        issuingCommonName          = $issuingCn
        issuingValidityDays        = $IssuingValidityDays
        signerValidityDays         = $SignerValidityDays
        rootCrlDays                = $RootCrlDays
        issuingCrlDays             = $IssuingCrlDays
        openssl                    = $script:OpenSslVersion
    }
    Save-Json -Path (Join-Path $IssuingCaPath 'issuing-request-metadata.json') -Object $metadata
    $requestConfig = Join-Path $IssuingCaPath 'issuing-request.cnf'
    New-IssuingRequestConfig -Path $requestConfig -Metadata $metadata

    $issuingPassword = Read-ValidatedPassphrase -Prompt 'Enter a new Issuing CA private-key passphrase'
    $secretFile = New-TemporarySecretFile -Secret $issuingPassword -Label 'issuing-ca'
    $passwordSource = Get-OpenSslPasswordSource -SecretFilePath $secretFile
    try {
        $issuingKey = Join-Path $IssuingCaPath 'private\issuing-ca.key.pem'
        $issuingCsr = Join-Path $IssuingCaPath 'csr\issuing-ca.csr.pem'

        Invoke-OpenSsl -Arguments @('genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:4096', '-aes-256-cbc', '-pass', $passwordSource, '-out', $issuingKey) -Description 'generating Issuing CA private key'
        Set-RestrictedAcl -Path $issuingKey -IncludeAdministrators
        Invoke-OpenSsl -Arguments @('pkey', '-in', $issuingKey, '-passin', $passwordSource, '-check', '-noout') -Description 'checking Issuing CA private key'
        Invoke-OpenSsl -Arguments @('req', '-new', '-sha384', '-config', $requestConfig, '-key', $issuingKey, '-passin', $passwordSource, '-out', $issuingCsr) -Description 'creating Issuing CA CSR'
        Invoke-OpenSsl -Arguments @('req', '-in', $issuingCsr, '-verify', '-noout') -Description 'verifying Issuing CA CSR'
        $csrSubject = Invoke-OpenSsl -Arguments @('req', '-in', $issuingCsr, '-noout', '-subject', '-nameopt', 'RFC2253') -Description 'reading Issuing CA CSR subject' -PassThru
        $csrSha256 = (Get-FileHash -LiteralPath $issuingCsr -Algorithm SHA256).Hash.ToUpperInvariant()
        $metadata | Add-Member -NotePropertyName 'csrSubject' -NotePropertyValue $csrSubject -Force
        $metadata | Add-Member -NotePropertyName 'csrSha256' -NotePropertyValue $csrSha256 -Force
        Save-Json -Path (Join-Path $IssuingCaPath 'issuing-request-metadata.json') -Object $metadata

        $transferCsr = Join-Path $TransferPath 'issuing-ca.csr.pem'
        $transferMetadata = Join-Path $TransferPath 'issuing-request-metadata.json'
        Copy-FileAtomic -Source $issuingCsr -Destination $transferCsr
        Copy-FileAtomic -Source (Join-Path $IssuingCaPath 'issuing-request-metadata.json') -Destination $transferMetadata
        Write-ChecksumManifest -Directory $TransferPath -RelativeFiles @('issuing-ca.csr.pem', 'issuing-request-metadata.json')

        Write-AuditEvent -BasePath $IssuingCaPath -EventAction 'IssuingCaRequestCreated' -Details @{
            csr          = $issuingCsr
            transferPath = $TransferPath
        }
        Write-Host "Issuing CA CSR created: $issuingCsr"
        Write-Host "Copy these files to approved removable media for the offline Root CA: $TransferPath"
        Write-Warning 'Do not copy issuing-ca.key.pem to the Root CA computer.'
    }
    finally {
        Remove-TemporarySecretFile -Path $secretFile
    }
}

function Invoke-SignIssuingRequest {
    Test-ChecksumManifest -Directory $TransferPath -RequiredRelativeFiles @(
        'issuing-ca.csr.pem',
        'issuing-request-metadata.json'
    )
    $csrPath = Join-Path $TransferPath 'issuing-ca.csr.pem'
    $requestMetadataPath = Join-Path $TransferPath 'issuing-request-metadata.json'
    if (-not (Test-Path -LiteralPath $csrPath -PathType Leaf)) {
        throw "Issuing CA CSR not found: $csrPath"
    }
    if (-not (Test-Path -LiteralPath $requestMetadataPath -PathType Leaf)) {
        throw "Issuing request metadata not found: $requestMetadataPath"
    }
    $rootMetadata = Read-Json -Path (Join-Path $RootCaPath 'pki-metadata.json')
    $requestMetadata = Read-Json -Path $requestMetadataPath
    if ([int] $rootMetadata.schemaVersion -ne 1 -or [string] $rootMetadata.caType -cne 'RootCA') {
        throw 'The offline Root CA metadata is invalid or unsupported.'
    }
    if ([string] $requestMetadata.caType -cne 'IssuingCARequest') {
        throw 'The transfer metadata is not an IssuingCARequest record.'
    }
    if ([int] $requestMetadata.schemaVersion -ne 1) {
        throw "Unsupported issuing-request metadata schema version: $($requestMetadata.schemaVersion)"
    }
    if ($rootMetadata.organization -cne $requestMetadata.organization) {
        throw "Issuing CA organization '$($requestMetadata.organization)' does not exactly match Root CA organization '$($rootMetadata.organization)'."
    }
    if ($rootMetadata.pkiBaseUrl -cne $requestMetadata.pkiBaseUrl) {
        throw 'Issuing request PkiBaseUrl does not match the Root CA PkiBaseUrl.'
    }
    if ([string] $rootMetadata.ocspUrl -cne [string] $requestMetadata.ocspUrl) {
        throw 'Issuing request OcspUrl does not match the Root CA policy metadata.'
    }
    if ($rootMetadata.country -cne $requestMetadata.country) {
        throw 'Issuing request country does not match the Root CA country.'
    }
    if ([int] $requestMetadata.issuingValidityDays -lt 1 -or [int] $requestMetadata.issuingValidityDays -gt [int] $rootMetadata.issuingValidityDays) {
        throw "Issuing request validity ($($requestMetadata.issuingValidityDays) days) exceeds the Root CA policy maximum ($($rootMetadata.issuingValidityDays) days), or is invalid."
    }
    if ([int] $requestMetadata.signerValidityDays -lt 30 -or [int] $requestMetadata.signerValidityDays -gt [int] $rootMetadata.signerValidityDays) {
        throw "Signer validity in the request ($($requestMetadata.signerValidityDays) days) exceeds the Root CA policy maximum ($($rootMetadata.signerValidityDays) days), or is invalid."
    }
    if ([int] $requestMetadata.issuingCrlDays -lt 1 -or [int] $requestMetadata.issuingCrlDays -gt [int] $rootMetadata.issuingCrlDays) {
        throw "Issuing request CRL lifetime ($($requestMetadata.issuingCrlDays) days) exceeds the Root CA policy maximum ($($rootMetadata.issuingCrlDays) days), or is invalid."
    }

    $actualCsrHash = (Get-FileHash -LiteralPath $csrPath -Algorithm SHA256).Hash.ToUpperInvariant()
    if ([string] $requestMetadata.csrSha256 -cne $actualCsrHash) {
        throw 'The Issuing CA CSR SHA-256 hash does not match the request metadata.'
    }
    $csrSubject = Invoke-OpenSsl -Arguments @('req', '-in', $csrPath, '-noout', '-subject', '-nameopt', 'RFC2253') -Description 'reading imported Issuing CA CSR subject' -PassThru
    if ([string] $requestMetadata.csrSubject -cne $csrSubject) {
        throw 'The Issuing CA CSR subject does not match the request metadata.'
    }
    Write-Host "Issuing CA CSR subject to be approved: $csrSubject"
    Write-Host "Transfer bundle SHA-256 manifest verified: $(Join-Path $TransferPath 'SHA256SUMS.txt')"

    Write-Section 'SIGN ISSUING CA CSR ON OFFLINE ROOT CA'
    if (-not $PSCmdlet.ShouldProcess($csrPath, 'Issue a subordinate Issuing CA certificate from the offline Root CA')) {
        return
    }

    Invoke-OpenSsl -Arguments @('req', '-in', $csrPath, '-verify', '-noout') -Description 'verifying imported Issuing CA CSR'
    Test-CertificateCanOutlive -IssuerCertificate (Join-Path $RootCaPath 'certs\root-ca.cert.pem') -RequestedDays ([int] $requestMetadata.issuingValidityDays)

    $rootPassword = Read-ValidatedPassphrase -Prompt 'Enter the Root CA private-key passphrase'
    $secretFile = New-TemporarySecretFile -Secret $rootPassword -Label 'root-ca'
    $passwordSource = Get-OpenSslPasswordSource -SecretFilePath $secretFile
    try {
        $rootConfig = Join-Path $RootCaPath 'openssl-root.cnf'
        $issuingCert = Join-Path $RootCaPath 'certs\issuing-ca.cert.pem'
        $issuingCertDer = Join-Path $RootCaPath 'certs\issuing-ca.cert.der'
        Invoke-OpenSslCa -BasePath $RootCaPath -Arguments @('ca', '-batch', '-config', $rootConfig, '-extensions', 'v3_intermediate_ca', '-days', [string] $requestMetadata.issuingValidityDays, '-notext', '-md', 'sha384', '-in', $csrPath, '-out', $issuingCert, '-passin', $passwordSource) -Description 'issuing subordinate Issuing CA certificate'
        Invoke-OpenSsl -Arguments @('x509', '-in', $issuingCert, '-outform', 'DER', '-out', $issuingCertDer) -Description 'converting Issuing CA certificate to DER'
        Invoke-OpenSsl -Arguments @('verify', '-x509_strict', '-show_chain', '-CAfile', (Join-Path $RootCaPath 'certs\root-ca.cert.pem'), $issuingCert) -Description 'verifying Issuing CA certificate'
        New-Crl -CaType Root -BasePath $RootCaPath -PasswordSource $passwordSource

        $resolvedBundlePath = if ([string]::IsNullOrWhiteSpace($BundlePath)) { Join-Path $TransferPath 'issuing-ca-signed-bundle' } else { $BundlePath }
        if (Test-Path -LiteralPath $resolvedBundlePath) {
            $existing = Get-ChildItem -LiteralPath $resolvedBundlePath -Force -ErrorAction SilentlyContinue
            if ($existing.Count -gt 0) {
                throw "Refusing to overwrite non-empty bundle directory: $resolvedBundlePath"
            }
        }
        [System.IO.Directory]::CreateDirectory($resolvedBundlePath) | Out-Null

        Copy-FileAtomic -Source $csrPath -Destination (Join-Path $resolvedBundlePath 'issuing-ca.csr.pem')
        Copy-FileAtomic -Source $issuingCert -Destination (Join-Path $resolvedBundlePath 'issuing-ca.cert.pem')
        Copy-FileAtomic -Source $issuingCertDer -Destination (Join-Path $resolvedBundlePath 'issuing-ca.cer')
        Copy-FileAtomic -Source (Join-Path $RootCaPath 'certs\root-ca.cert.pem') -Destination (Join-Path $resolvedBundlePath 'root-ca.cert.pem')
        Copy-FileAtomic -Source (Join-Path $RootCaPath 'certs\root-ca.cert.der') -Destination (Join-Path $resolvedBundlePath 'root-ca.cer')
        Copy-FileAtomic -Source (Join-Path $RootCaPath 'crl\root-ca.crl.pem') -Destination (Join-Path $resolvedBundlePath 'root-ca.crl.pem')
        Copy-FileAtomic -Source (Join-Path $RootCaPath 'crl\root-ca.crl.der') -Destination (Join-Path $resolvedBundlePath 'root-ca.crl')
        Join-PemFiles -InputFiles @($issuingCert, (Join-Path $RootCaPath 'certs\root-ca.cert.pem')) -OutputFile (Join-Path $resolvedBundlePath 'issuing-ca-chain.cert.pem')

        $bundleMetadata = [pscustomobject][ordered]@{
            schemaVersion             = 1
            caType                    = 'SignedIssuingCABundle'
            createdUtc                = [DateTime]::UtcNow.ToString('o')
            pkiBaseUrl                = $rootMetadata.pkiBaseUrl
            ocspUrl                   = $rootMetadata.ocspUrl
            country                   = $requestMetadata.country
            stateOrProvince           = $requestMetadata.stateOrProvince
            locality                  = $requestMetadata.locality
            organization              = $requestMetadata.organization
            issuingOrganizationalUnit = $requestMetadata.issuingOrganizationalUnit
            issuingCommonName         = $requestMetadata.issuingCommonName
            issuingValidityDays       = $requestMetadata.issuingValidityDays
            signerValidityDays        = $requestMetadata.signerValidityDays
            issuingCrlDays            = $requestMetadata.issuingCrlDays
            csrSubject                = $requestMetadata.csrSubject
            csrSha256                 = $requestMetadata.csrSha256
            rootFingerprint           = Get-NormalizedCertificateFingerprint -Certificate (Join-Path $RootCaPath 'certs\root-ca.cert.pem')
            issuingFingerprint        = Get-NormalizedCertificateFingerprint -Certificate $issuingCert
            openssl                   = $script:OpenSslVersion
        }
        Save-Json -Path (Join-Path $resolvedBundlePath 'bundle-metadata.json') -Object $bundleMetadata
        Write-ChecksumManifest -Directory $resolvedBundlePath -RelativeFiles @(
            'issuing-ca.csr.pem',
            'issuing-ca.cert.pem',
            'issuing-ca.cer',
            'root-ca.cert.pem',
            'root-ca.cer',
            'root-ca.crl.pem',
            'root-ca.crl',
            'issuing-ca-chain.cert.pem',
            'bundle-metadata.json'
        )

        Write-AuditEvent -BasePath $RootCaPath -EventAction 'IssuingCaCertificateIssued' -Details @{
            certificate = $issuingCert
            bundle      = $resolvedBundlePath
            fingerprint = $bundleMetadata.issuingFingerprint
        }
        Write-Host "Issuing CA certificate issued: $issuingCert"
        Write-Host "Signed transfer bundle: $resolvedBundlePath"
        Write-Warning 'Copy only the signed bundle back to the Issuing CA computer. Keep the Root CA offline.'
    }
    finally {
        Remove-TemporarySecretFile -Path $secretFile
    }
}

function Invoke-FinalizeIssuing {
    Assert-RequiredValue -Name 'ExpectedRootFingerprint' -Value $ExpectedRootFingerprint
    $expectedRootFingerprintNormalized = Normalize-Sha256Fingerprint -Value $ExpectedRootFingerprint -Name 'ExpectedRootFingerprint'
    $resolvedBundlePath = if ([string]::IsNullOrWhiteSpace($BundlePath)) { Join-Path $TransferPath 'issuing-ca-signed-bundle' } else { $BundlePath }
    Test-ChecksumManifest -Directory $resolvedBundlePath -RequiredRelativeFiles @(
        'issuing-ca.csr.pem',
        'issuing-ca.cert.pem',
        'issuing-ca.cer',
        'root-ca.cert.pem',
        'root-ca.cer',
        'root-ca.crl.pem',
        'root-ca.crl',
        'issuing-ca-chain.cert.pem',
        'bundle-metadata.json'
    )
    $metadata = Read-Json -Path (Join-Path $resolvedBundlePath 'bundle-metadata.json')
    if ([int] $metadata.schemaVersion -ne 1) {
        throw "Unsupported signed-bundle metadata schema version: $($metadata.schemaVersion)"
    }
    if ([string] $metadata.caType -cne 'SignedIssuingCABundle') {
        throw 'The returned metadata is not a SignedIssuingCABundle record.'
    }

    $issuingKey = Join-Path $IssuingCaPath 'private\issuing-ca.key.pem'
    $localCsr = Join-Path $IssuingCaPath 'csr\issuing-ca.csr.pem'
    $localRequestMetadataPath = Join-Path $IssuingCaPath 'issuing-request-metadata.json'
    foreach ($requiredPath in @($issuingKey, $localCsr, $localRequestMetadataPath)) {
        if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
            throw "Required local Issuing CA file not found: $requiredPath"
        }
    }

    $localRequestMetadata = Read-Json -Path $localRequestMetadataPath
    foreach ($propertyName in @(
        'pkiBaseUrl',
        'ocspUrl',
        'country',
        'stateOrProvince',
        'locality',
        'organization',
        'issuingOrganizationalUnit',
        'issuingCommonName',
        'issuingValidityDays',
        'signerValidityDays',
        'issuingCrlDays',
        'csrSubject',
        'csrSha256'
    )) {
        Assert-PropertyEqual -ExpectedObject $localRequestMetadata -ActualObject $metadata -PropertyName $propertyName -Context 'Signed bundle versus local Issuing CA request metadata'
    }

    $bundleCsr = Join-Path $resolvedBundlePath 'issuing-ca.csr.pem'
    $bundleIssuingCert = Join-Path $resolvedBundlePath 'issuing-ca.cert.pem'
    $bundleRootCert = Join-Path $resolvedBundlePath 'root-ca.cert.pem'
    $bundleRootCrl = Join-Path $resolvedBundlePath 'root-ca.crl.pem'
    foreach ($requiredPath in @($bundleCsr, $bundleIssuingCert, $bundleRootCert, $bundleRootCrl)) {
        if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
            throw "Required signed-bundle file not found: $requiredPath"
        }
    }

    $localCsrHash = (Get-FileHash -LiteralPath $localCsr -Algorithm SHA256).Hash.ToUpperInvariant()
    $bundleCsrHash = (Get-FileHash -LiteralPath $bundleCsr -Algorithm SHA256).Hash.ToUpperInvariant()
    if ($localCsrHash -cne $bundleCsrHash -or $localCsrHash -cne [string] $metadata.csrSha256) {
        throw 'The signed bundle CSR does not match the CSR retained on the Issuing CA computer.'
    }

    Invoke-OpenSsl -Arguments @('req', '-in', $bundleCsr, '-verify', '-noout') -Description 'verifying signed-bundle Issuing CA CSR'
    Test-CsrMatchesCertificate -Csr $bundleCsr -Certificate $bundleIssuingCert
    Invoke-OpenSsl -Arguments @('verify', '-x509_strict', '-show_chain', '-CAfile', $bundleRootCert, $bundleIssuingCert) -Description 'verifying signed-bundle Issuing CA chain'
    Invoke-OpenSsl -Arguments @('crl', '-in', $bundleRootCrl, '-noout', '-verify', '-CAfile', $bundleRootCert) -Description 'verifying signed-bundle Root CA CRL'
    Invoke-OpenSsl -Arguments @('verify', '-x509_strict', '-CAfile', $bundleRootCert, '-CRLfile', $bundleRootCrl, '-crl_check', $bundleIssuingCert) -Description 'verifying that the signed-bundle Issuing CA is not revoked and the Root CRL is current'

    $bundleRootFingerprint = Get-NormalizedCertificateFingerprint -Certificate $bundleRootCert
    $bundleIssuingFingerprint = Get-NormalizedCertificateFingerprint -Certificate $bundleIssuingCert
    if ($bundleRootFingerprint -cne (Normalize-Sha256Fingerprint -Value ([string] $metadata.rootFingerprint) -Name 'Bundle metadata Root fingerprint')) {
        throw 'The Root CA certificate fingerprint does not match the signed-bundle metadata.'
    }
    if ($bundleIssuingFingerprint -cne (Normalize-Sha256Fingerprint -Value ([string] $metadata.issuingFingerprint) -Name 'Bundle metadata Issuing fingerprint')) {
        throw 'The Issuing CA certificate fingerprint does not match the signed-bundle metadata.'
    }
    if ($bundleRootFingerprint -cne $expectedRootFingerprintNormalized) {
        throw 'The Root CA certificate fingerprint does not match the independently recorded ExpectedRootFingerprint.'
    }

    $csrSubject = Invoke-OpenSsl -Arguments @('req', '-in', $bundleCsr, '-noout', '-subject', '-nameopt', 'RFC2253') -Description 'reading signed-bundle CSR subject' -PassThru
    $certificateSubject = Invoke-OpenSsl -Arguments @('x509', '-in', $bundleIssuingCert, '-noout', '-subject', '-nameopt', 'RFC2253') -Description 'reading signed Issuing CA certificate subject' -PassThru
    if ($csrSubject -cne $certificateSubject) {
        throw 'The signed Issuing CA certificate subject does not exactly match the approved CSR subject.'
    }

    Write-Host "Verified Root CA SHA-256 fingerprint: $bundleRootFingerprint"
    Write-Host "Verified Issuing CA SHA-256 fingerprint: $bundleIssuingFingerprint"

    Write-Section 'FINALIZE ISSUING CA'
    if (-not $PSCmdlet.ShouldProcess($IssuingCaPath, 'Install the independently verified signed Issuing CA certificate, create CA configuration, verify the key pair, and generate the initial Issuing CRL')) {
        return
    }

    Copy-FileAtomic -Source (Join-Path $resolvedBundlePath 'issuing-ca.cert.pem') -Destination (Join-Path $IssuingCaPath 'certs\issuing-ca.cert.pem')
    Copy-FileAtomic -Source (Join-Path $resolvedBundlePath 'issuing-ca.cer') -Destination (Join-Path $IssuingCaPath 'certs\issuing-ca.cert.der')
    Copy-FileAtomic -Source (Join-Path $resolvedBundlePath 'root-ca.cert.pem') -Destination (Join-Path $IssuingCaPath 'certs\root-ca.cert.pem')
    Copy-FileAtomic -Source (Join-Path $resolvedBundlePath 'root-ca.cer') -Destination (Join-Path $IssuingCaPath 'certs\root-ca.cert.der')
    Copy-FileAtomic -Source (Join-Path $resolvedBundlePath 'root-ca.crl.pem') -Destination (Join-Path $IssuingCaPath 'crl\root-ca.crl.pem')
    Copy-FileAtomic -Source (Join-Path $resolvedBundlePath 'root-ca.crl') -Destination (Join-Path $IssuingCaPath 'crl\root-ca.crl.der')
    Copy-FileAtomic -Source (Join-Path $resolvedBundlePath 'issuing-ca-chain.cert.pem') -Destination (Join-Path $IssuingCaPath 'certs\issuing-ca-chain.cert.pem')
    $installedRootFingerprint = Get-NormalizedCertificateFingerprint -Certificate (Join-Path $IssuingCaPath 'certs\root-ca.cert.pem')
    $installedIssuingFingerprint = Get-NormalizedCertificateFingerprint -Certificate (Join-Path $IssuingCaPath 'certs\issuing-ca.cert.pem')
    if ($installedRootFingerprint -cne $bundleRootFingerprint) {
        throw 'Installed Root CA certificate fingerprint changed during installation.'
    }
    if ($installedIssuingFingerprint -cne $bundleIssuingFingerprint) {
        throw 'Installed Issuing CA certificate fingerprint changed during installation.'
    }

    Save-Json -Path (Join-Path $IssuingCaPath 'pki-metadata.json') -Object $metadata
    New-IssuingOpenSslConfig -BasePath $IssuingCaPath -Metadata $metadata

    $issuingPassword = Read-ValidatedPassphrase -Prompt 'Enter the Issuing CA private-key passphrase'
    $secretFile = New-TemporarySecretFile -Secret $issuingPassword -Label 'issuing-ca'
    $passwordSource = Get-OpenSslPasswordSource -SecretFilePath $secretFile
    try {
        Invoke-OpenSsl -Arguments @('pkey', '-in', $issuingKey, '-passin', $passwordSource, '-check', '-noout') -Description 'checking Issuing CA private key'
        Test-KeyMatchesCertificate -PrivateKey $issuingKey -Certificate (Join-Path $IssuingCaPath 'certs\issuing-ca.cert.pem') -PasswordSource $passwordSource
        Invoke-OpenSsl -Arguments @('verify', '-x509_strict', '-show_chain', '-CAfile', (Join-Path $IssuingCaPath 'certs\root-ca.cert.pem'), (Join-Path $IssuingCaPath 'certs\issuing-ca.cert.pem')) -Description 'verifying installed Issuing CA chain'
        New-Crl -CaType Issuing -BasePath $IssuingCaPath -PasswordSource $passwordSource

        Write-AuditEvent -BasePath $IssuingCaPath -EventAction 'IssuingCaFinalized' -Details @{
            certificate = (Join-Path $IssuingCaPath 'certs\issuing-ca.cert.pem')
            fingerprint = $metadata.issuingFingerprint
            publish     = (Join-Path $IssuingCaPath 'publish')
        }
        Write-Host "Issuing CA is ready: $IssuingCaPath"
        Write-Host "Publish the four DER files from: $(Join-Path $IssuingCaPath 'publish')"
        Write-Warning 'The URLs embedded in certificates must serve the exact .cer and .crl files without authentication.'
    }
    finally {
        Remove-TemporarySecretFile -Path $secretFile
    }
}

function Invoke-IssueDocumentSigner {
    Assert-RequiredValue -Name 'SignerCommonName' -Value $SignerCommonName
    Assert-RequiredValue -Name 'SignerEmail' -Value $SignerEmail
    if ($SignerEmail -notmatch '^[^\s@]+@[^\s@]+\.[^\s@]+$') {
        throw 'SignerEmail is not in a recognizable email-address format.'
    }
    foreach ($entry in @{
        SignerCommonName = $SignerCommonName; SignerEmail = $SignerEmail; SignerTitle = $SignerTitle;
        SignerOrganization = $SignerOrganization; SignerOrganizationalUnit = $SignerOrganizationalUnit
    }.GetEnumerator()) {
        Assert-NoNewLine -Name $entry.Key -Value ([string] $entry.Value)
    }

    $metadata = Read-Json -Path (Join-Path $IssuingCaPath 'pki-metadata.json')
    $signerOrg = if ([string]::IsNullOrWhiteSpace($SignerOrganization)) { [string] $metadata.organization } else { $SignerOrganization }
    $subject = [pscustomobject][ordered]@{
        country            = [string] $metadata.country
        stateOrProvince    = [string] $metadata.stateOrProvince
        locality           = [string] $metadata.locality
        organization       = $signerOrg
        organizationalUnit = $SignerOrganizationalUnit
        title              = $SignerTitle
        commonName         = $SignerCommonName
        email              = $SignerEmail
    }

    $effectiveSignerValidityDays = if ($script:InvocationBoundParameters.ContainsKey('SignerValidityDays')) {
        $SignerValidityDays
    }
    else {
        [int] $metadata.signerValidityDays
    }
    if ($effectiveSignerValidityDays -gt [int] $metadata.signerValidityDays) {
        throw "Requested signer validity ($effectiveSignerValidityDays days) exceeds the Issuing CA policy maximum ($($metadata.signerValidityDays) days)."
    }

    $rootCert = Join-Path $IssuingCaPath 'certs\root-ca.cert.pem'
    $issuingCert = Join-Path $IssuingCaPath 'certs\issuing-ca.cert.pem'
    $rootCrl = Join-Path $IssuingCaPath 'crl\root-ca.crl.pem'
    foreach ($requiredPath in @($rootCert, $issuingCert, $rootCrl)) {
        if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
            throw "Required Issuing CA trust or revocation file not found: $requiredPath"
        }
    }
    Test-CertificateCanOutlive -IssuerCertificate $issuingCert -RequestedDays $effectiveSignerValidityDays
    Invoke-OpenSsl -Arguments @('verify', '-x509_strict', '-CAfile', $rootCert, '-CRLfile', $rootCrl, '-crl_check', $issuingCert) -Description 'verifying that the Issuing CA is trusted, not revoked, and covered by a current Root CRL before signer issuance'

    $slug = Get-SafeFileName -Value $SignerCommonName
    $issuanceId = (Get-Date -Format 'yyyyMMddHHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
    $signerPath = Join-Path $IssuedPath ($slug + '-' + $issuanceId)

    Write-Section 'ISSUE DOCUMENT-SIGNING CERTIFICATE'
    if (-not $PSCmdlet.ShouldProcess($signerPath, "Generate signer key, CSR, document-signing certificate, chain, and PFX for '$SignerCommonName'")) {
        return
    }

    [System.IO.Directory]::CreateDirectory($signerPath) | Out-Null
    Set-RestrictedAcl -Path $signerPath -Directory -IncludeAdministrators
    foreach ($sub in @('private', 'csr', 'certs', 'pfx')) {
        [System.IO.Directory]::CreateDirectory((Join-Path $signerPath $sub)) | Out-Null
    }
    Set-RestrictedAcl -Path (Join-Path $signerPath 'private') -Directory -IncludeAdministrators
    Set-RestrictedAcl -Path (Join-Path $signerPath 'pfx') -Directory -IncludeAdministrators

    $requestConfig = Join-Path $signerPath 'signer-request.cnf'
    $extensionConfig = Join-Path $signerPath 'signer-extensions.cnf'
    New-SignerRequestConfig -Path $requestConfig -Subject $subject
    New-SignerExtensionConfig -Path $extensionConfig -Metadata $metadata -Email $SignerEmail

    $issuingPassword = Read-ValidatedPassphrase -Prompt 'Enter the Issuing CA private-key passphrase'
    $signerKeyPassword = Read-ValidatedPassphrase -Prompt 'Enter a new document-signer private-key passphrase'
    $issuingSecretFile = New-TemporarySecretFile -Secret $issuingPassword -Label 'issuing-ca'
    $signerSecretFile = New-TemporarySecretFile -Secret $signerKeyPassword -Label 'document-signer'
    $pfxSecretFile = $null
    try {
        $issuingPasswordSource = Get-OpenSslPasswordSource -SecretFilePath $issuingSecretFile
        $signerPasswordSource = Get-OpenSslPasswordSource -SecretFilePath $signerSecretFile
        $signerKey = Join-Path $signerPath "private\$slug.key.pem"
        $signerCsr = Join-Path $signerPath "csr\$slug.csr.pem"
        $signerCert = Join-Path $signerPath "certs\$slug.cert.pem"
        $signerCertDer = Join-Path $signerPath "certs\$slug.cer"
        $signerFullChain = Join-Path $signerPath "certs\$slug-fullchain.cert.pem"
        $caChain = Join-Path $IssuingCaPath 'certs\issuing-ca-chain.cert.pem'
        $pfxFile = Join-Path $signerPath "pfx\$slug.pfx"

        Invoke-OpenSsl -Arguments @('genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:3072', '-aes-256-cbc', '-pass', $signerPasswordSource, '-out', $signerKey) -Description 'generating document-signer private key'
        Set-RestrictedAcl -Path $signerKey -IncludeAdministrators
        Invoke-OpenSsl -Arguments @('pkey', '-in', $signerKey, '-passin', $signerPasswordSource, '-check', '-noout') -Description 'checking document-signer private key'
        Invoke-OpenSsl -Arguments @('req', '-new', '-sha256', '-config', $requestConfig, '-key', $signerKey, '-passin', $signerPasswordSource, '-out', $signerCsr) -Description 'creating document-signer CSR'
        Invoke-OpenSsl -Arguments @('req', '-in', $signerCsr, '-verify', '-noout') -Description 'verifying document-signer CSR'
        Invoke-OpenSslCa -BasePath $IssuingCaPath -Arguments @('ca', '-batch', '-config', (Join-Path $IssuingCaPath 'openssl-issuing.cnf'), '-extfile', $extensionConfig, '-extensions', 'document_signer', '-days', [string] $effectiveSignerValidityDays, '-notext', '-md', 'sha256', '-in', $signerCsr, '-out', $signerCert, '-passin', $issuingPasswordSource) -Description 'issuing document-signing certificate'
        Invoke-OpenSsl -Arguments @('x509', '-in', $signerCert, '-outform', 'DER', '-out', $signerCertDer) -Description 'converting document-signer certificate to DER'
        Test-KeyMatchesCertificate -PrivateKey $signerKey -Certificate $signerCert -PasswordSource $signerPasswordSource
        Join-PemFiles -InputFiles @($signerCert, (Join-Path $IssuingCaPath 'certs\issuing-ca.cert.pem'), $rootCert) -OutputFile $signerFullChain

        New-Crl -CaType Issuing -BasePath $IssuingCaPath -PasswordSource $issuingPasswordSource
        Verify-SignerCertificateChain -IssuingPath $IssuingCaPath -SignerCertificate $signerCert

        if (-not $SkipPfx) {
            $pfxPassword = Read-ValidatedPassphrase -Prompt 'Enter a new PFX import/export password'
            $pfxSecretFile = New-TemporarySecretFile -Secret $pfxPassword -Label 'pfx'
            $pfxPasswordSource = Get-OpenSslPasswordSource -SecretFilePath $pfxSecretFile
            $pfxArguments = @(
                'pkcs12', '-export',
                '-inkey', $signerKey,
                '-passin', $signerPasswordSource,
                '-in', $signerCert,
                '-certfile', $caChain,
                '-name', "$SignerCommonName - Document Signing",
                '-keysig',
                '-keypbe', 'AES-256-CBC',
                '-certpbe', 'AES-256-CBC',
                '-macalg', 'SHA256',
                '-iter', [string] $PfxIterations
            )
            if ($script:SupportsPfxMacSaltLength) {
                $pfxArguments += @('-macsaltlen', '16')
            }
            else {
                Write-Warning 'This OpenSSL build does not support -macsaltlen. The PFX will use the implementation default MAC salt length. OpenSSL 3.3 or later is recommended.'
            }
            $pfxArguments += @('-passout', $pfxPasswordSource, '-out', $pfxFile)
            Invoke-OpenSsl -Arguments $pfxArguments -Description 'exporting document signer as PKCS#12/PFX'
            Set-RestrictedAcl -Path $pfxFile -IncludeAdministrators
            Invoke-OpenSsl -Arguments @('pkcs12', '-in', $pfxFile, '-passin', $pfxPasswordSource, '-info', '-noout') -Description 'validating generated PFX'
        }

        $certificateMetadata = [pscustomobject][ordered]@{
            schemaVersion        = 1
            issuanceId           = $issuanceId
            issuedUtc            = [DateTime]::UtcNow.ToString('o')
            validityDays         = $effectiveSignerValidityDays
            signer               = $subject
            certificatePath      = $signerCert
            certificateDerPath   = $signerCertDer
            fullChainPath        = $signerFullChain
            pfxPath              = if ($SkipPfx) { $null } else { $pfxFile }
            serial               = Get-CertificateProperty -Certificate $signerCert -Property serial
            fingerprint          = Get-CertificateProperty -Certificate $signerCert -Property fingerprint
            subject              = Get-CertificateProperty -Certificate $signerCert -Property subject
            issuer               = Get-CertificateProperty -Certificate $signerCert -Property issuer
            validity             = Get-CertificateProperty -Certificate $signerCert -Property dates
            documentSigningEkus  = @(
                '1.3.6.1.5.5.7.3.36',
                '1.3.6.1.4.1.311.10.3.12',
                '1.2.840.113583.1.1.5'
            )
            openssl              = $script:OpenSslVersion
            pfxMacSaltLength16   = $script:SupportsPfxMacSaltLength
        }
        Save-Json -Path (Join-Path $signerPath 'certificate-metadata.json') -Object $certificateMetadata
        $manifestFiles = @(
            "csr\$slug.csr.pem",
            "certs\$slug.cert.pem",
            "certs\$slug.cer",
            "certs\$slug-fullchain.cert.pem",
            'signer-request.cnf',
            'signer-extensions.cnf',
            'certificate-metadata.json'
        )
        if (-not $SkipPfx) {
            $manifestFiles += "pfx\$slug.pfx"
        }
        Write-ChecksumManifest -Directory $signerPath -RelativeFiles $manifestFiles

        Write-AuditEvent -BasePath $IssuingCaPath -EventAction 'DocumentSignerCertificateIssued' -Details @{
            signer       = $SignerCommonName
            email        = $SignerEmail
            certificate  = $signerCert
            serial       = $certificateMetadata.serial
            fingerprint  = $certificateMetadata.fingerprint
        }
        Write-Host "Document-signing certificate created: $signerCert"
        if (-not $SkipPfx) {
            Write-Host "PFX for Windows/Acrobat/Office import: $pfxFile"
        }
        Write-Host "Signer package directory: $signerPath"
        Write-Warning 'After importing the PFX as non-exportable, move the PFX to an approved encrypted backup vault or destroy the working copy under your key-management policy.'
    }
    finally {
        Remove-TemporarySecretFile -Path $issuingSecretFile
        Remove-TemporarySecretFile -Path $signerSecretFile
        Remove-TemporarySecretFile -Path $pfxSecretFile
    }
}

function Invoke-GenerateRootCrl {
    $rootPassword = Read-ValidatedPassphrase -Prompt 'Enter the Root CA private-key passphrase'
    $secretFile = New-TemporarySecretFile -Secret $rootPassword -Label 'root-ca'
    try {
        New-Crl -CaType Root -BasePath $RootCaPath -PasswordSource (Get-OpenSslPasswordSource -SecretFilePath $secretFile)
        Write-AuditEvent -BasePath $RootCaPath -EventAction 'RootCrlGenerated' -Details @{ crl = (Join-Path $RootCaPath 'crl\root-ca.crl.pem') }
        Write-Host "Root CRL generated: $(Join-Path $RootCaPath 'publish\root-ca.crl')"
    }
    finally {
        Remove-TemporarySecretFile -Path $secretFile
    }
}

function Invoke-GenerateIssuingCrl {
    $issuingPassword = Read-ValidatedPassphrase -Prompt 'Enter the Issuing CA private-key passphrase'
    $secretFile = New-TemporarySecretFile -Secret $issuingPassword -Label 'issuing-ca'
    try {
        New-Crl -CaType Issuing -BasePath $IssuingCaPath -PasswordSource (Get-OpenSslPasswordSource -SecretFilePath $secretFile)
        Write-AuditEvent -BasePath $IssuingCaPath -EventAction 'IssuingCrlGenerated' -Details @{ crl = (Join-Path $IssuingCaPath 'crl\issuing-ca.crl.pem') }
        Write-Host "Issuing CRL generated: $(Join-Path $IssuingCaPath 'publish\issuing-ca.crl')"
    }
    finally {
        Remove-TemporarySecretFile -Path $secretFile
    }
}

function Invoke-RevokeDocumentSigner {
    Assert-RequiredValue -Name 'CertificatePath' -Value $CertificatePath
    if (-not (Test-Path -LiteralPath $CertificatePath -PathType Leaf)) {
        throw "Certificate not found: $CertificatePath"
    }
    Write-Section 'REVOKE DOCUMENT-SIGNING CERTIFICATE'
    if (-not $PSCmdlet.ShouldProcess($CertificatePath, "Revoke certificate with reason '$RevocationReason' and publish a new Issuing CA CRL")) {
        return
    }

    $issuingPassword = Read-ValidatedPassphrase -Prompt 'Enter the Issuing CA private-key passphrase'
    $secretFile = New-TemporarySecretFile -Secret $issuingPassword -Label 'issuing-ca'
    try {
        $passwordSource = Get-OpenSslPasswordSource -SecretFilePath $secretFile
        Invoke-OpenSslCa -BasePath $IssuingCaPath -Arguments @('ca', '-config', (Join-Path $IssuingCaPath 'openssl-issuing.cnf'), '-revoke', $CertificatePath, '-crl_reason', $RevocationReason, '-passin', $passwordSource) -Description 'revoking document signer certificate'
        New-Crl -CaType Issuing -BasePath $IssuingCaPath -PasswordSource $passwordSource
        $serial = Get-CertificateProperty -Certificate $CertificatePath -Property serial
        Write-AuditEvent -BasePath $IssuingCaPath -EventAction 'DocumentSignerCertificateRevoked' -Details @{
            certificate = $CertificatePath
            serial      = $serial
            reason      = $RevocationReason
        }
        Write-Host "Certificate revoked: $serial"
        Write-Host "Publish the updated CRL immediately: $(Join-Path $IssuingCaPath 'publish\issuing-ca.crl')"
    }
    finally {
        Remove-TemporarySecretFile -Path $secretFile
    }
}

function Invoke-RevokeIssuingCA {
    Assert-RequiredValue -Name 'CertificatePath' -Value $CertificatePath
    if (-not (Test-Path -LiteralPath $CertificatePath -PathType Leaf)) {
        throw "Issuing CA certificate not found: $CertificatePath"
    }
    Write-Section 'REVOKE ISSUING CA CERTIFICATE'
    if (-not $PSCmdlet.ShouldProcess($CertificatePath, "Revoke Issuing CA certificate with reason '$RevocationReason' and publish a new Root CA CRL")) {
        return
    }

    $rootPassword = Read-ValidatedPassphrase -Prompt 'Enter the Root CA private-key passphrase'
    $secretFile = New-TemporarySecretFile -Secret $rootPassword -Label 'root-ca'
    try {
        $passwordSource = Get-OpenSslPasswordSource -SecretFilePath $secretFile
        Invoke-OpenSslCa -BasePath $RootCaPath -Arguments @('ca', '-config', (Join-Path $RootCaPath 'openssl-root.cnf'), '-revoke', $CertificatePath, '-crl_reason', $RevocationReason, '-passin', $passwordSource) -Description 'revoking Issuing CA certificate'
        New-Crl -CaType Root -BasePath $RootCaPath -PasswordSource $passwordSource
        Write-AuditEvent -BasePath $RootCaPath -EventAction 'IssuingCaCertificateRevoked' -Details @{
            certificate = $CertificatePath
            reason      = $RevocationReason
        }
        Write-Host "Issuing CA certificate revoked. Publish the updated Root CRL immediately: $(Join-Path $RootCaPath 'publish\root-ca.crl')"
        Write-Warning 'Stop all issuance from the revoked Issuing CA and begin incident response and replacement procedures.'
    }
    finally {
        Remove-TemporarySecretFile -Path $secretFile
    }
}

function Invoke-VerifyDocumentSigner {
    Assert-RequiredValue -Name 'CertificatePath' -Value $CertificatePath
    if (-not (Test-Path -LiteralPath $CertificatePath -PathType Leaf)) {
        throw "Certificate not found: $CertificatePath"
    }
    Write-Section 'VERIFY DOCUMENT-SIGNING CERTIFICATE'
    Verify-SignerCertificateChain -IssuingPath $IssuingCaPath -SignerCertificate $CertificatePath
    $details = Invoke-OpenSsl -Arguments @('x509', '-in', $CertificatePath, '-noout', '-subject', '-issuer', '-serial', '-dates', '-fingerprint', '-sha256', '-ext', 'basicConstraints,keyUsage,extendedKeyUsage,subjectAltName,authorityInfoAccess,crlDistributionPoints') -Description 'inspecting document signer certificate' -PassThru
    Write-Host $details
}

function Invoke-InstallTrust {
    if (-not $script:IsWindowsPlatform) {
        throw 'InstallTrust is supported only on Windows.'
    }
    if ($TrustScope -eq 'LocalMachine' -and -not (Test-IsAdministrator)) {
        throw 'InstallTrust -TrustScope LocalMachine must run from an elevated PowerShell session.'
    }
    Assert-RequiredValue -Name 'ExpectedRootFingerprint' -Value $ExpectedRootFingerprint
    $expectedRootFingerprintNormalized = Normalize-Sha256Fingerprint -Value $ExpectedRootFingerprint -Name 'ExpectedRootFingerprint'
    $rootDer = Join-Path $IssuingCaPath 'certs\root-ca.cert.der'
    $rootPem = Join-Path $IssuingCaPath 'certs\root-ca.cert.pem'
    $issuingDer = Join-Path $IssuingCaPath 'certs\issuing-ca.cert.der'
    $issuingPem = Join-Path $IssuingCaPath 'certs\issuing-ca.cert.pem'
    foreach ($path in @($rootDer, $rootPem, $issuingDer, $issuingPem)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Required certificate file not found: $path"
        }
    }
    $actualRootFingerprint = Get-NormalizedCertificateFingerprint -Certificate $rootPem
    if ($actualRootFingerprint -cne $expectedRootFingerprintNormalized) {
        throw 'Refusing to install trust because the Root CA fingerprint does not match ExpectedRootFingerprint.'
    }
    Invoke-OpenSsl -Arguments @('verify', '-x509_strict', '-show_chain', '-CAfile', $rootPem, $issuingPem) -Description 'verifying the private PKI chain before installing trust'
    $rootCrl = Join-Path $IssuingCaPath 'crl\root-ca.crl.pem'
    if (-not (Test-Path -LiteralPath $rootCrl -PathType Leaf)) {
        throw "Required Root CA CRL not found: $rootCrl"
    }
    Invoke-OpenSsl -Arguments @('verify', '-x509_strict', '-CAfile', $rootPem, '-CRLfile', $rootCrl, '-crl_check', $issuingPem) -Description 'verifying that the Issuing CA is not revoked and the Root CRL is current before installing trust'
    Write-Host "Verified Root CA SHA-256 fingerprint: $actualRootFingerprint"

    $rootStore = if ($TrustScope -eq 'LocalMachine') { 'Cert:\LocalMachine\Root' } else { 'Cert:\CurrentUser\Root' }
    $issuingStore = if ($TrustScope -eq 'LocalMachine') { 'Cert:\LocalMachine\CA' } else { 'Cert:\CurrentUser\CA' }
    Write-Section "INSTALL PRIVATE PKI TRUST INTO WINDOWS ($TrustScope)"
    if (-not $PSCmdlet.ShouldProcess($rootStore, 'Trust the private Root CA and install the Issuing CA certificate')) {
        return
    }
    $rootResult = Import-Certificate -FilePath $rootDer -CertStoreLocation $rootStore
    $issuingResult = Import-Certificate -FilePath $issuingDer -CertStoreLocation $issuingStore
    Write-Host "Root CA installed in $rootStore; thumbprint: $($rootResult.Thumbprint)"
    Write-Host "Issuing CA installed in $issuingStore; thumbprint: $($issuingResult.Thumbprint)"
    Write-Warning 'This trusts the private CA only on the selected Windows scope. It does not enroll the CA in Adobe AATL or the Microsoft Trusted Root Program.'
}

function Invoke-InstallSignerPfx {
    if (-not $script:IsWindowsPlatform) {
        throw 'InstallSignerPfx is supported only on Windows.'
    }
    Assert-RequiredValue -Name 'PfxPath' -Value $PfxPath
    if (-not (Test-Path -LiteralPath $PfxPath -PathType Leaf)) {
        throw "PFX file not found: $PfxPath"
    }
    Write-Section 'INSTALL DOCUMENT SIGNER PFX INTO CURRENT USER CERTIFICATE STORE'
    if (-not $PSCmdlet.ShouldProcess('Cert:\CurrentUser\My', "Import PFX '$PfxPath' as a non-exportable private key")) {
        return
    }
    $password = Read-Host -Prompt 'Enter the PFX password' -AsSecureString
    $result = Import-PfxCertificate -FilePath $PfxPath -CertStoreLocation 'Cert:\CurrentUser\My' -Password $password
    Write-Host "Signer certificate installed as non-exportable in Cert:\CurrentUser\My; thumbprint: $($result.Thumbprint)"
}

Resolve-OpenSsl
Write-Verbose "Using $script:OpenSslVersion at $script:OpenSslExecutable"

switch ($Action) {
    'InitializeRoot'          { Invoke-InitializeRoot }
    'CreateIssuingRequest'    { Invoke-CreateIssuingRequest }
    'SignIssuingRequest'      { Invoke-SignIssuingRequest }
    'FinalizeIssuing'         { Invoke-FinalizeIssuing }
    'IssueDocumentSigner'     { Invoke-IssueDocumentSigner }
    'GenerateRootCrl'         { Invoke-GenerateRootCrl }
    'GenerateIssuingCrl'      { Invoke-GenerateIssuingCrl }
    'RevokeDocumentSigner'    { Invoke-RevokeDocumentSigner }
    'RevokeIssuingCA'         { Invoke-RevokeIssuingCA }
    'VerifyDocumentSigner'    { Invoke-VerifyDocumentSigner }
    'InstallTrust'            { Invoke-InstallTrust }
    'InstallSignerPfx'        { Invoke-InstallSignerPfx }
    default                   { throw "Unhandled action: $Action" }
}
