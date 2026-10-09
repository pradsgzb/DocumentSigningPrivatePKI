#requires -Version 5.1
<#
Edit the organization, URL, names, and paths below before running this file.
This wrapper deliberately preserves the confirmation prompts in
PrivateDocumentPki.ps1. It never accepts passwords as parameters.
#>

[CmdletBinding()]
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
        'VerifyDocumentSigner',
        'InstallTrust',
        'InstallSignerPfx',
        'RevokeDocumentSigner',
        'RevokeIssuingCA'
    )]
    [string] $Step,

    [string] $SignerCommonName,
    [string] $SignerEmail,
    [string] $SignerTitle,
    [string] $CertificatePath,
    [string] $PfxPath,

    [ValidateSet(
        'unspecified',
        'keyCompromise',
        'CACompromise',
        'affiliationChanged',
        'superseded',
        'cessationOfOperation',
        'certificateHold'
    )]
    [string] $RevocationReason = 'keyCompromise'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# -----------------------------------------------------------------------------
# MANDATORY SITE CONFIGURATION — REPLACE EVERY CHANGE-ME VALUE
# -----------------------------------------------------------------------------
$Organization = 'CHANGE-ME EXACT LEGAL ORGANIZATION NAME'
$Country = 'US'
$StateOrProvince = 'North Carolina'
$Locality = 'Fayetteville'
$PkiBaseUrl = 'https://CHANGE-ME-PKI-HOST.example/document-signing'

$RootCommonName = 'CHANGE-ME ORGANIZATION Root CA 2026'
$IssuingCommonName = 'CHANGE-ME ORGANIZATION Document Signing Issuing CA 2026'
# After InitializeRoot, copy the independently recorded 64-hex SHA-256 fingerprint here.
$ExpectedRootFingerprint = 'CHANGE-ME ROOT SHA256 FINGERPRINT'

$OpenSslPath = 'C:\Program Files\OpenSSL-Win64\bin\openssl.exe'
$RootCaPath = 'E:\PrivatePKI\RootCA'
$IssuingCaPath = 'D:\PrivatePKI\IssuingCA'
$TransferPath = 'F:\PKI-Transfer\Issuing-Request'
$SignedBundlePath = 'F:\PKI-Transfer\Issuing-Signed-Bundle'
$IssuedPath = 'D:\PrivatePKI\Issued'

$PkiScript = Join-Path $PSScriptRoot 'PrivateDocumentPki.ps1'

$configurationValues = @(
    $Organization,
    $PkiBaseUrl,
    $RootCommonName,
    $IssuingCommonName
)
if (@($configurationValues | Where-Object { $_ -match 'CHANGE-ME' }).Count -gt 0) {
    throw 'Replace every required organization, URL, and CA-name CHANGE-ME value before using this wrapper.'
}
if ($Step -in @('FinalizeIssuing', 'InstallTrust') -and $ExpectedRootFingerprint -match 'CHANGE-ME') {
    throw 'Record the Root CA SHA-256 fingerprint from InitializeRoot and replace ExpectedRootFingerprint before this step.'
}
if (-not (Test-Path -LiteralPath $PkiScript -PathType Leaf)) {
    throw "Primary PKI script was not found: $PkiScript"
}

$identityParameters = @{
    OpenSslPath          = $OpenSslPath
    PkiBaseUrl           = $PkiBaseUrl
    Country              = $Country
    StateOrProvince      = $StateOrProvince
    Locality             = $Locality
    Organization         = $Organization
    RootCommonName       = $RootCommonName
    IssuingCommonName    = $IssuingCommonName
    RootValidityDays     = 7305
    IssuingValidityDays  = 3652
    SignerValidityDays   = 730
    RootCrlDays          = 365
    IssuingCrlDays       = 7
    PfxIterations        = 200000
}

switch ($Step) {
    'InitializeRoot' {
        & $PkiScript InitializeRoot @identityParameters -RootCaPath $RootCaPath
    }
    'CreateIssuingRequest' {
        & $PkiScript CreateIssuingRequest @identityParameters `
            -IssuingCaPath $IssuingCaPath `
            -TransferPath $TransferPath
    }
    'SignIssuingRequest' {
        & $PkiScript SignIssuingRequest `
            -OpenSslPath $OpenSslPath `
            -RootCaPath $RootCaPath `
            -TransferPath $TransferPath `
            -BundlePath $SignedBundlePath
    }
    'FinalizeIssuing' {
        & $PkiScript FinalizeIssuing `
            -OpenSslPath $OpenSslPath `
            -IssuingCaPath $IssuingCaPath `
            -BundlePath $SignedBundlePath `
            -ExpectedRootFingerprint $ExpectedRootFingerprint
    }
    'IssueDocumentSigner' {
        foreach ($required in @{
            SignerCommonName = $SignerCommonName
            SignerEmail      = $SignerEmail
            SignerTitle      = $SignerTitle
        }.GetEnumerator()) {
            if ([string]::IsNullOrWhiteSpace([string] $required.Value)) {
                throw "-$($required.Key) is required for IssueDocumentSigner."
            }
        }
        & $PkiScript IssueDocumentSigner `
            -OpenSslPath $OpenSslPath `
            -IssuingCaPath $IssuingCaPath `
            -IssuedPath $IssuedPath `
            -SignerCommonName $SignerCommonName `
            -SignerEmail $SignerEmail `
            -SignerTitle $SignerTitle `
            -SignerOrganization $Organization
    }
    'GenerateRootCrl' {
        & $PkiScript GenerateRootCrl `
            -OpenSslPath $OpenSslPath `
            -RootCaPath $RootCaPath
    }
    'GenerateIssuingCrl' {
        & $PkiScript GenerateIssuingCrl `
            -OpenSslPath $OpenSslPath `
            -IssuingCaPath $IssuingCaPath
    }
    'VerifyDocumentSigner' {
        if ([string]::IsNullOrWhiteSpace($CertificatePath)) {
            throw '-CertificatePath is required for VerifyDocumentSigner.'
        }
        & $PkiScript VerifyDocumentSigner `
            -OpenSslPath $OpenSslPath `
            -IssuingCaPath $IssuingCaPath `
            -CertificatePath $CertificatePath
    }
    'InstallTrust' {
        & $PkiScript InstallTrust `
            -OpenSslPath $OpenSslPath `
            -IssuingCaPath $IssuingCaPath `
            -TrustScope LocalMachine `
            -ExpectedRootFingerprint $ExpectedRootFingerprint
    }
    'InstallSignerPfx' {
        if ([string]::IsNullOrWhiteSpace($PfxPath)) {
            throw '-PfxPath is required for InstallSignerPfx.'
        }
        & $PkiScript InstallSignerPfx `
            -OpenSslPath $OpenSslPath `
            -PfxPath $PfxPath
    }
    'RevokeDocumentSigner' {
        if ([string]::IsNullOrWhiteSpace($CertificatePath)) {
            throw '-CertificatePath is required for RevokeDocumentSigner.'
        }
        & $PkiScript RevokeDocumentSigner `
            -OpenSslPath $OpenSslPath `
            -IssuingCaPath $IssuingCaPath `
            -CertificatePath $CertificatePath `
            -RevocationReason $RevocationReason
    }
    'RevokeIssuingCA' {
        if ([string]::IsNullOrWhiteSpace($CertificatePath)) {
            throw '-CertificatePath is required for RevokeIssuingCA.'
        }
        & $PkiScript RevokeIssuingCA `
            -OpenSslPath $OpenSslPath `
            -RootCaPath $RootCaPath `
            -CertificatePath $CertificatePath `
            -RevocationReason $RevocationReason
    }
}
