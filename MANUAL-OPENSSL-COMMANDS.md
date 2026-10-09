# Exact OpenSSL Commands for a Two-Tier Private Document-Signing PKI

These are the command-line operations implemented by `PrivateDocumentPki.ps1`. They are provided for review, troubleshooting, and controlled manual ceremonies. The PowerShell script is safer for routine use because it validates inputs, protects temporary password files, locks the CA database, backs up CA state, creates checksums, and verifies each output.

## Critical distinction

These commands create certificates and a PFX. OpenSSL does **not** turn the final two commands into an embedded PAdES PDF signature or an OPC/DOCX signature. Import the PFX into Windows or use a hardware token, then sign through Adobe Acrobat/Reader, Microsoft Word, or an appropriate signing library.

## Assumptions used below

```powershell
$OpenSsl = 'C:\Program Files\OpenSSL-Win64\bin\openssl.exe'
$Root    = 'C:\PrivatePKI\RootCA'
$Issuing = 'C:\PrivatePKI\IssuingCA'
$Signer  = 'C:\PrivatePKI\Signer-NAME'
$Config  = 'C:\PKI-Tools\manual-config-examples'

$RootPassFile    = 'C:\SecureTemp\root-ca.secret'
$IssuingPassFile = 'C:\SecureTemp\issuing-ca.secret'
$SignerPassFile  = 'C:\SecureTemp\signer.secret'
$PfxPassFile     = 'C:\SecureTemp\signer-pfx.secret'

$RootPass    = 'file:' + $RootPassFile.Replace('\', '/')
$IssuingPass = 'file:' + $IssuingPassFile.Replace('\', '/')
$SignerPass  = 'file:' + $SignerPassFile.Replace('\', '/')
$PfxPass     = 'file:' + $PfxPassFile.Replace('\', '/')
```

Each password file must contain only the password, must have a restricted ACL, and must be securely removed immediately after the operation. Do not put passwords directly in the command line, script source, shell history, environment variables, email, or tickets.

Before running the commands, edit every `CHANGE-ME` value in the five configuration files in `manual-config-examples`.

## 1. Create directory structures and CA databases

```powershell
$RootDirectories = @(
  $Root,
  "$Root\certs", "$Root\crl", "$Root\csr", "$Root\db",
  "$Root\newcerts", "$Root\private", "$Root\publish", "$Root\logs"
)
$IssuingDirectories = @(
  $Issuing,
  "$Issuing\certs", "$Issuing\crl", "$Issuing\csr", "$Issuing\db",
  "$Issuing\newcerts", "$Issuing\private", "$Issuing\publish", "$Issuing\logs"
)
$SignerDirectories = @(
  $Signer,
  "$Signer\certs", "$Signer\csr", "$Signer\private", "$Signer\pfx"
)

$RootDirectories + $IssuingDirectories + $SignerDirectories |
  ForEach-Object { [System.IO.Directory]::CreateDirectory($_) | Out-Null }

[System.IO.File]::WriteAllText("$Root\db\index.txt", '')
[System.IO.File]::WriteAllText("$Root\db\index.txt.attr", "unique_subject = no`r`n")
[System.IO.File]::WriteAllText("$Root\db\serial", ((& $OpenSsl rand -hex 16).Trim() + "`r`n"))
[System.IO.File]::WriteAllText("$Root\db\crlnumber", "1000`r`n")

[System.IO.File]::WriteAllText("$Issuing\db\index.txt", '')
[System.IO.File]::WriteAllText("$Issuing\db\index.txt.attr", "unique_subject = no`r`n")
[System.IO.File]::WriteAllText("$Issuing\db\serial", ((& $OpenSsl rand -hex 16).Trim() + "`r`n"))
[System.IO.File]::WriteAllText("$Issuing\db\crlnumber", "1000`r`n")

Copy-Item "$Config\openssl-root.cnf" "$Root\openssl-root.cnf"
Copy-Item "$Config\issuing-request.cnf" "$Issuing\issuing-request.cnf"
Copy-Item "$Config\openssl-issuing.cnf" "$Issuing\openssl-issuing.cnf"
Copy-Item "$Config\signer-request.cnf" "$Signer\signer-request.cnf"
Copy-Item "$Config\signer-extensions.cnf" "$Signer\signer-extensions.cnf"
```

Apply restrictive ACLs before continuing. The primary script does this automatically.

## 2. Generate the offline Root CA private key

```powershell
& $OpenSsl genpkey `
  -algorithm RSA `
  -pkeyopt rsa_keygen_bits:4096 `
  -aes-256-cbc `
  -pass $RootPass `
  -out "$Root\private\root-ca.key.pem"

if ($LASTEXITCODE -ne 0) { throw 'Root private-key generation failed.' }

& $OpenSsl pkey `
  -in "$Root\private\root-ca.key.pem" `
  -passin $RootPass `
  -check `
  -noout

if ($LASTEXITCODE -ne 0) { throw 'Root private-key validation failed.' }
```

## 3. Create the self-signed Root CA certificate

```powershell
$RootSerial = '0x' + ((& $OpenSsl rand -hex 16).Trim())

& $OpenSsl req `
  -config "$Root\openssl-root.cnf" `
  -key "$Root\private\root-ca.key.pem" `
  -passin $RootPass `
  -new `
  -x509 `
  -days 7305 `
  -sha384 `
  -set_serial $RootSerial `
  -extensions v3_root_ca `
  -out "$Root\certs\root-ca.cert.pem"

if ($LASTEXITCODE -ne 0) { throw 'Root certificate creation failed.' }

& $OpenSsl x509 `
  -in "$Root\certs\root-ca.cert.pem" `
  -outform DER `
  -out "$Root\certs\root-ca.cert.der"

& $OpenSsl verify `
  -x509_strict `
  -check_ss_sig `
  -CAfile "$Root\certs\root-ca.cert.pem" `
  "$Root\certs\root-ca.cert.pem"

if ($LASTEXITCODE -ne 0) { throw 'Root certificate verification failed.' }
```

Expected Root constraints:

```text
Basic Constraints: critical, CA:TRUE, pathlen:1
Key Usage: critical, Certificate Sign, CRL Sign
```

Inspect them:

```powershell
& $OpenSsl x509 `
  -in "$Root\certs\root-ca.cert.pem" `
  -noout `
  -subject -issuer -serial -dates -fingerprint -sha256 `
  -ext basicConstraints,keyUsage,subjectKeyIdentifier,authorityKeyIdentifier
```

Record and independently verify the Root fingerprint. The value below must be the 64 hexadecimal SHA-256 characters recorded during the Root ceremony, not a value copied from the returned Issuing CA bundle:

```powershell
$ExpectedRootFingerprint = 'REPLACE-WITH-64-HEX-SHA256-FINGERPRINT'
if ($ExpectedRootFingerprint -notmatch '^[0-9A-Fa-f]{64}$') {
  throw 'ExpectedRootFingerprint must contain exactly 64 hexadecimal characters.'
}

$FingerprintOutput = (& $OpenSsl x509 `
  -in "$Root\certs\root-ca.cert.pem" `
  -noout -fingerprint -sha256).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Unable to read the Root certificate fingerprint.' }

$ActualRootFingerprint = (($FingerprintOutput -split '=', 2)[1] -replace ':', '').ToUpperInvariant()
if ($ActualRootFingerprint -cne $ExpectedRootFingerprint.ToUpperInvariant()) {
  throw 'Root certificate fingerprint mismatch.'
}
```

## 4. Generate the initial Root CRL

```powershell
& $OpenSsl ca `
  -config "$Root\openssl-root.cnf" `
  -gencrl `
  -out "$Root\crl\root-ca.crl.pem" `
  -passin $RootPass

if ($LASTEXITCODE -ne 0) { throw 'Root CRL generation failed.' }

& $OpenSsl crl `
  -in "$Root\crl\root-ca.crl.pem" `
  -outform DER `
  -out "$Root\crl\root-ca.crl.der"

& $OpenSsl crl `
  -in "$Root\crl\root-ca.crl.pem" `
  -noout -issuer -lastupdate -nextupdate -crlnumber
```

## 5. Generate the Issuing CA private key and CSR

Run this on the Issuing CA computer:

```powershell
& $OpenSsl genpkey `
  -algorithm RSA `
  -pkeyopt rsa_keygen_bits:4096 `
  -aes-256-cbc `
  -pass $IssuingPass `
  -out "$Issuing\private\issuing-ca.key.pem"

if ($LASTEXITCODE -ne 0) { throw 'Issuing CA private-key generation failed.' }

& $OpenSsl pkey `
  -in "$Issuing\private\issuing-ca.key.pem" `
  -passin $IssuingPass `
  -check `
  -noout

& $OpenSsl req `
  -new `
  -sha384 `
  -config "$Issuing\issuing-request.cnf" `
  -key "$Issuing\private\issuing-ca.key.pem" `
  -passin $IssuingPass `
  -out "$Issuing\csr\issuing-ca.csr.pem"

& $OpenSsl req `
  -in "$Issuing\csr\issuing-ca.csr.pem" `
  -verify `
  -noout

& $OpenSsl req `
  -in "$Issuing\csr\issuing-ca.csr.pem" `
  -noout `
  -subject `
  -nameopt RFC2253

if ($LASTEXITCODE -ne 0) { throw 'Issuing CA CSR verification failed.' }
```

Transfer only the CSR and approved request metadata to the offline Root CA. Never transfer the Issuing CA private key.

## 6. Sign the Issuing CA CSR with the offline Root CA

Run on the offline Root CA after reviewing and approving the CSR subject:

```powershell
& $OpenSsl ca `
  -batch `
  -config "$Root\openssl-root.cnf" `
  -extensions v3_intermediate_ca `
  -days 3652 `
  -notext `
  -md sha384 `
  -in "$Issuing\csr\issuing-ca.csr.pem" `
  -out "$Issuing\certs\issuing-ca.cert.pem" `
  -passin $RootPass

if ($LASTEXITCODE -ne 0) { throw 'Issuing CA certificate issuance failed.' }

& $OpenSsl x509 `
  -in "$Issuing\certs\issuing-ca.cert.pem" `
  -outform DER `
  -out "$Issuing\certs\issuing-ca.cert.der"

& $OpenSsl verify `
  -x509_strict `
  -show_chain `
  -CAfile "$Root\certs\root-ca.cert.pem" `
  "$Issuing\certs\issuing-ca.cert.pem"

if ($LASTEXITCODE -ne 0) { throw 'Issuing CA certificate verification failed.' }
```

Expected Issuing CA constraints:

```text
Basic Constraints: critical, CA:TRUE, pathlen:0
Key Usage: critical, Certificate Sign, CRL Sign
```

The `pathlen:0` constraint prevents the Issuing CA from creating another subordinate CA.

## 7. Verify and install the Root certificate and chain on the Issuing CA computer

Before copying any returned certificate into the Issuing CA directories, repeat the out-of-band Root fingerprint comparison above against the returned `root-ca.cert.pem`, verify that the returned CSR is byte-for-byte identical to the CSR retained locally, and run:

```powershell
& $OpenSsl req -in "$Issuing\csr\issuing-ca.csr.pem" -verify -noout
& $OpenSsl verify -x509_strict -show_chain `
  -CAfile "$Root\certs\root-ca.cert.pem" `
  "$Issuing\certs\issuing-ca.cert.pem"
if ($LASTEXITCODE -ne 0) { throw 'Returned Issuing CA chain verification failed.' }
```

Then install the verified public files:

```powershell
Copy-Item "$Root\certs\root-ca.cert.pem" "$Issuing\certs\root-ca.cert.pem"
Copy-Item "$Root\certs\root-ca.cert.der" "$Issuing\certs\root-ca.cert.der"
Copy-Item "$Root\crl\root-ca.crl.pem" "$Issuing\crl\root-ca.crl.pem"
Copy-Item "$Root\crl\root-ca.crl.der" "$Issuing\crl\root-ca.crl.der"

$IssuingPem = [System.IO.File]::ReadAllText("$Issuing\certs\issuing-ca.cert.pem").Trim()
$RootPem = [System.IO.File]::ReadAllText("$Issuing\certs\root-ca.cert.pem").Trim()
[System.IO.File]::WriteAllText(
  "$Issuing\certs\issuing-ca-chain.cert.pem",
  $IssuingPem + [Environment]::NewLine + $RootPem + [Environment]::NewLine,
  [System.Text.Encoding]::ASCII
)
```

## 8. Generate the initial Issuing CA CRL

```powershell
& $OpenSsl ca `
  -config "$Issuing\openssl-issuing.cnf" `
  -gencrl `
  -out "$Issuing\crl\issuing-ca.crl.pem" `
  -passin $IssuingPass

if ($LASTEXITCODE -ne 0) { throw 'Issuing CA CRL generation failed.' }

& $OpenSsl crl `
  -in "$Issuing\crl\issuing-ca.crl.pem" `
  -outform DER `
  -out "$Issuing\crl\issuing-ca.crl.der"
```

## 9. Generate a document-signer private key

```powershell
& $OpenSsl genpkey `
  -algorithm RSA `
  -pkeyopt rsa_keygen_bits:3072 `
  -aes-256-cbc `
  -pass $SignerPass `
  -out "$Signer\private\document-signer.key.pem"

if ($LASTEXITCODE -ne 0) { throw 'Signer private-key generation failed.' }

& $OpenSsl pkey `
  -in "$Signer\private\document-signer.key.pem" `
  -passin $SignerPass `
  -check `
  -noout
```

## 10. Create and verify the signer CSR

```powershell
& $OpenSsl req `
  -new `
  -sha256 `
  -config "$Signer\signer-request.cnf" `
  -key "$Signer\private\document-signer.key.pem" `
  -passin $SignerPass `
  -out "$Signer\csr\document-signer.csr.pem"

& $OpenSsl req `
  -in "$Signer\csr\document-signer.csr.pem" `
  -verify `
  -noout

if ($LASTEXITCODE -ne 0) { throw 'Signer CSR verification failed.' }
```

## 11. Issue the document-signing certificate

```powershell
& $OpenSsl ca `
  -batch `
  -config "$Issuing\openssl-issuing.cnf" `
  -extfile "$Signer\signer-extensions.cnf" `
  -extensions document_signer `
  -days 730 `
  -notext `
  -md sha256 `
  -in "$Signer\csr\document-signer.csr.pem" `
  -out "$Signer\certs\document-signer.cert.pem" `
  -passin $IssuingPass

if ($LASTEXITCODE -ne 0) { throw 'Document-signer certificate issuance failed.' }

& $OpenSsl x509 `
  -in "$Signer\certs\document-signer.cert.pem" `
  -outform DER `
  -out "$Signer\certs\document-signer.cer"
```

Expected signer restrictions:

```text
Basic Constraints: critical, CA:FALSE
Key Usage: critical, Digital Signature, Non Repudiation
Extended Key Usage:
  1.3.6.1.5.5.7.3.36
  1.3.6.1.4.1.311.10.3.12
  1.2.840.113583.1.1.5
```

Inspect the certificate:

```powershell
& $OpenSsl x509 `
  -in "$Signer\certs\document-signer.cert.pem" `
  -noout `
  -subject -issuer -serial -dates -fingerprint -sha256 `
  -ext basicConstraints,keyUsage,extendedKeyUsage,subjectAltName,authorityInfoAccess,crlDistributionPoints
```

## 12. Verify the certificate chain

Cryptographic chain verification:

```powershell
& $OpenSsl verify `
  -x509_strict `
  -show_chain `
  -CAfile "$Issuing\certs\root-ca.cert.pem" `
  -untrusted "$Issuing\certs\issuing-ca.cert.pem" `
  "$Signer\certs\document-signer.cert.pem"

if ($LASTEXITCODE -ne 0) { throw 'Signer chain verification failed.' }
```

CRL-aware verification:

```powershell
$IssuingCrlPem = [System.IO.File]::ReadAllText("$Issuing\crl\issuing-ca.crl.pem").Trim()
$RootCrlPem = [System.IO.File]::ReadAllText("$Issuing\crl\root-ca.crl.pem").Trim()
$CombinedCrl = "$env:TEMP\all-document-pki-crls.pem"
[System.IO.File]::WriteAllText(
  $CombinedCrl,
  $IssuingCrlPem + [Environment]::NewLine + $RootCrlPem + [Environment]::NewLine,
  [System.Text.Encoding]::ASCII
)

& $OpenSsl verify `
  -x509_strict `
  -CAfile "$Issuing\certs\root-ca.cert.pem" `
  -untrusted "$Issuing\certs\issuing-ca.cert.pem" `
  -CRLfile $CombinedCrl `
  -crl_check_all `
  "$Signer\certs\document-signer.cert.pem"

if ($LASTEXITCODE -ne 0) { throw 'Signer CRL verification failed.' }
Remove-Item $CombinedCrl -Force
```

## 13. Export the signer as PKCS#12/PFX

For OpenSSL 3.3 or later:

```powershell
& $OpenSsl pkcs12 `
  -export `
  -inkey "$Signer\private\document-signer.key.pem" `
  -passin $SignerPass `
  -in "$Signer\certs\document-signer.cert.pem" `
  -certfile "$Issuing\certs\issuing-ca-chain.cert.pem" `
  -name 'FULL LEGAL NAME - Document Signing' `
  -keysig `
  -keypbe AES-256-CBC `
  -certpbe AES-256-CBC `
  -macalg SHA256 `
  -iter 200000 `
  -macsaltlen 16 `
  -passout $PfxPass `
  -out "$Signer\pfx\document-signer.pfx"

if ($LASTEXITCODE -ne 0) { throw 'PFX export failed.' }
```

For OpenSSL 3.0–3.2, omit `-macsaltlen 16`; those releases do not expose that option.

Validate the PFX structure without extracting private material:

```powershell
& $OpenSsl pkcs12 `
  -in "$Signer\pfx\document-signer.pfx" `
  -passin $PfxPass `
  -info `
  -noout

if ($LASTEXITCODE -ne 0) { throw 'PFX validation failed.' }
```

Expected modern output includes AES-256-CBC, PBKDF2, HMAC-SHA-256, and the configured iteration count.

## 14. Revoke a signer certificate and publish a fresh CRL

```powershell
& $OpenSsl ca `
  -config "$Issuing\openssl-issuing.cnf" `
  -revoke "$Signer\certs\document-signer.cert.pem" `
  -crl_reason keyCompromise `
  -passin $IssuingPass

if ($LASTEXITCODE -ne 0) { throw 'Certificate revocation failed.' }

& $OpenSsl ca `
  -config "$Issuing\openssl-issuing.cnf" `
  -gencrl `
  -out "$Issuing\crl\issuing-ca.crl.pem" `
  -passin $IssuingPass

& $OpenSsl crl `
  -in "$Issuing\crl\issuing-ca.crl.pem" `
  -outform DER `
  -out "$Issuing\crl\issuing-ca.crl.der"
```

After publishing the new CRL, CRL-aware verification must fail with a certificate-revoked error.

## 15. Revoke the Issuing CA from the Root CA

Run only on the offline Root CA under an approved incident or decommissioning procedure:

```powershell
& $OpenSsl ca `
  -config "$Root\openssl-root.cnf" `
  -revoke "$Issuing\certs\issuing-ca.cert.pem" `
  -crl_reason CACompromise `
  -passin $RootPass

& $OpenSsl ca `
  -config "$Root\openssl-root.cnf" `
  -gencrl `
  -out "$Root\crl\root-ca.crl.pem" `
  -passin $RootPass

& $OpenSsl crl `
  -in "$Root\crl\root-ca.crl.pem" `
  -outform DER `
  -out "$Root\crl\root-ca.crl.der"
```

Publish the Root CRL immediately and stop all use of the revoked Issuing CA.

## 16. Verify that the private key matches its certificate

The safest generic comparison is to normalize and hash the public keys:

```powershell
$KeyPublicPem  = "$env:TEMP\key-public.pem"
$CertPublicPem = "$env:TEMP\cert-public.pem"
$KeyPublicDer  = "$env:TEMP\key-public.der"
$CertPublicDer = "$env:TEMP\cert-public.der"

& $OpenSsl pkey -in "$Signer\private\document-signer.key.pem" -passin $SignerPass -pubout -out $KeyPublicPem
& $OpenSsl x509 -in "$Signer\certs\document-signer.cert.pem" -pubkey -noout -out $CertPublicPem
& $OpenSsl pkey -pubin -in $KeyPublicPem -outform DER -out $KeyPublicDer
& $OpenSsl pkey -pubin -in $CertPublicPem -outform DER -out $CertPublicDer

$KeyHash  = (Get-FileHash $KeyPublicDer -Algorithm SHA256).Hash
$CertHash = (Get-FileHash $CertPublicDer -Algorithm SHA256).Hash
if ($KeyHash -cne $CertHash) { throw 'Private key does not match certificate.' }

Remove-Item $KeyPublicPem, $CertPublicPem, $KeyPublicDer, $CertPublicDer -Force
```

## Why a two-tier CA is used

Issuing a human certificate directly from the Root CA would require regular Root-key use and expose the most important key to routine operations. The two-tier design keeps the Root offline, permits Issuing CA replacement or revocation, and prevents the Issuing CA from creating additional CAs because its certificate is constrained with `pathLen:0`.
