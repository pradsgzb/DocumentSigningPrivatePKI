# Private Document-Signing PKI for PDF and Microsoft Word

This package creates a **private, two-tier public-key infrastructure (PKI)** for named document signers:

```text
Offline Root CA
  └── Document-Signing Issuing CA
        └── Individual Document-Signing Certificate(s)
```

It is designed for Windows PowerShell and OpenSSL. It creates encrypted private keys, CSRs, X.509 certificates, certificate chains, CRLs, DER/PEM publication files, PKCS#12/PFX signer packages, checksums, database backups, and operational audit records.

## Read this before creating a CA

A certificate issued by your own Root CA is cryptographically valid, but it is **not automatically trusted by outside recipients**. A relying computer must trust your Root CA, and Adobe Acrobat may require separate trusted-identity configuration. Creating a private CA does not enroll it in Adobe's Approved Trust List (AATL), the Microsoft Trusted Root Program, or an eIDAS trust list.

Use this private PKI when:

- signatures are primarily verified on organization-managed devices;
- you can deploy the Root CA through Group Policy, Intune, MDM, or another controlled method; and
- your recipients understand that this is an organization-private trust model.

Purchase an AATL/public document-signing certificate when arbitrary external recipients must receive automatic trust without installing your private Root CA.

This package **creates certificates**. It does not itself embed PAdES signatures in PDF files or OPC signatures in DOCX files. Use Adobe Acrobat/Reader, Microsoft Word, or a standards-compliant signing library after importing the signer PFX or connecting a hardware token/HSM.

## Cryptographic profile

| Component | Profile |
|---|---|
| Root CA | RSA 4096, SHA-384, `CA:true`, `pathLen:1`, 7,305-day default validity |
| Issuing CA | RSA 4096, SHA-384, `CA:true`, `pathLen:0`, 3,652-day default validity |
| Signer | RSA 3072, SHA-256, `CA:false`, 730-day default validity |
| Signer key usage | `digitalSignature`, `nonRepudiation` / content commitment |
| Signer EKUs | IETF document signing, Microsoft Office document signing, Adobe document signing |
| Key files | Encrypted PKCS#8 using AES-256-CBC |
| PFX | AES-256-CBC, PBKDF2, HMAC-SHA-256, 200,000 iterations; 16-byte MAC salt when supported |
| Revocation | Separate Root and Issuing CA CRLs |

Signer EKU OIDs:

```text
1.3.6.1.5.5.7.3.36          IETF document signing
1.3.6.1.4.1.311.10.3.12     Microsoft Office document signing
1.2.840.113583.1.1.5         Adobe document signing compatibility
```

The signer certificate intentionally does **not** include TLS server/client authentication, S/MIME email protection, or code-signing EKUs.

## Files in this package

- `PrivateDocumentPki.ps1` — primary lifecycle and operations script.
- `Example-Commands.ps1` — copy-ready action sequence with mandatory placeholders.
- `MANUAL-OPENSSL-COMMANDS.md` — exact OpenSSL commands and configuration anatomy.
- `SECURITY-OPERATIONS-CHECKLIST.md` — controls required around the technical scripts.
- `VALIDATION-REPORT.md` — verification performed on this package.
- `manual-config-examples/` — OpenSSL configuration examples matching the command guide.
- `SHA256SUMS.txt` — package file-integrity manifest.

## Prerequisites

1. **Windows PowerShell 5.1 or PowerShell 7.x.**
2. **OpenSSL 3.0 or later.** OpenSSL 3.3 or later is preferred because it supports explicitly setting a 16-byte PKCS#12 MAC salt.
3. A dedicated offline computer or encrypted removable operating environment for the Root CA.
4. A separate, tightly controlled Issuing CA workstation or server.
5. A stable HTTP or HTTPS publication URL that you control, such as:

   ```text
   https://pki.your-domain.example/document-signing
   ```

6. Approved encrypted backups and an approved password vault.
7. For high-assurance use, an HSM or hardware token. The supplied reference script creates software-protected keys; this is not equivalent to a non-exportable HSM key.

Use the **exact legal organization name** that your organization has approved. Do not copy the examples without review.

## Required publication files

The URL supplied through `-PkiBaseUrl` is embedded in the certificates. The following files must be reachable without authentication and must retain these exact names:

```text
root-ca.cer
root-ca.crl
issuing-ca.cer
issuing-ca.crl
```

The script also produces PEM copies for administration. The certificate and CRL URLs are effectively part of the certificate profile; changing the website later does not change URLs already embedded in issued certificates.

## Recommended machine separation

### Offline Root CA computer

Keep only:

- Root CA private key;
- Root CA database;
- Root CA certificate and CRL;
- approved transfer media; and
- the script and operating runbook.

Disconnect the Root CA from ordinary networks. Use it only to sign or revoke an Issuing CA certificate and to issue a fresh Root CRL.

### Issuing CA computer

Keep:

- Issuing CA private key and CA database;
- Issuing CA certificate and chain;
- signer issuance records;
- current Root and Issuing CRLs; and
- signer packages pending controlled distribution.

Do not copy the Root private key to this computer.

## Five-stage setup

The examples below use placeholders. Replace them before execution. The script prompts for all private-key and PFX passwords and does not accept them on the command line.

### 1. Initialize the offline Root CA

Run on the **offline Root CA computer**:

```powershell
$Script = 'E:\PKI-Tools\PrivateDocumentPki.ps1'
$OpenSsl = 'C:\Program Files\OpenSSL-Win64\bin\openssl.exe'

& $Script InitializeRoot `
  -OpenSslPath $OpenSsl `
  -RootCaPath 'E:\PrivatePKI\RootCA' `
  -PkiBaseUrl 'https://pki.your-domain.example/document-signing' `
  -Country 'US' `
  -StateOrProvince 'North Carolina' `
  -Locality 'Fayetteville' `
  -Organization 'YOUR EXACT LEGAL ORGANIZATION NAME' `
  -RootCommonName 'YOUR ORGANIZATION Root CA 2026'
```

Record the displayed SHA-256 Root certificate fingerprint in the approved PKI record. Preserve the 64 hexadecimal characters independently of the transfer media; the script requires this value when finalizing the Issuing CA and when installing private trust.

### 2. Create the Issuing CA key and CSR

Run on the **Issuing CA computer**:

```powershell
$Script = 'C:\PKI-Tools\PrivateDocumentPki.ps1'
$OpenSsl = 'C:\Program Files\OpenSSL-Win64\bin\openssl.exe'

& $Script CreateIssuingRequest `
  -OpenSslPath $OpenSsl `
  -IssuingCaPath 'D:\PrivatePKI\IssuingCA' `
  -TransferPath 'E:\PKI-Transfer\Issuing-Request' `
  -PkiBaseUrl 'https://pki.your-domain.example/document-signing' `
  -Country 'US' `
  -StateOrProvince 'North Carolina' `
  -Locality 'Fayetteville' `
  -Organization 'YOUR EXACT LEGAL ORGANIZATION NAME' `
  -IssuingCommonName 'YOUR ORGANIZATION Document Signing Issuing CA 2026'
```

Transfer only the following request bundle to the offline Root CA:

```text
issuing-ca.csr.pem
issuing-request-metadata.json
SHA256SUMS.txt
```

Never transfer `issuing-ca.key.pem` to the Root computer.

### 3. Sign the Issuing CA request on the offline Root CA

Copy the request bundle into a clean directory on approved media, then run on the **offline Root CA computer**:

```powershell
& 'E:\PKI-Tools\PrivateDocumentPki.ps1' SignIssuingRequest `
  -OpenSslPath 'C:\Program Files\OpenSSL-Win64\bin\openssl.exe' `
  -RootCaPath 'E:\PrivatePKI\RootCA' `
  -TransferPath 'F:\Issuing-Request' `
  -BundlePath 'F:\Issuing-Signed-Bundle'
```

The script verifies the request bundle checksums, displays the CSR subject for approval, applies the CA policy, creates the Issuing CA certificate, verifies the chain, creates an updated Root CRL, and creates a checksummed signed bundle.

### 4. Finalize the Issuing CA

Return the complete signed bundle to the **Issuing CA computer**, then run:

```powershell
& 'C:\PKI-Tools\PrivateDocumentPki.ps1' FinalizeIssuing `
  -OpenSslPath 'C:\Program Files\OpenSSL-Win64\bin\openssl.exe' `
  -IssuingCaPath 'D:\PrivatePKI\IssuingCA' `
  -BundlePath 'E:\PKI-Transfer\Issuing-Signed-Bundle' `
  -ExpectedRootFingerprint 'REPLACE-WITH-64-HEX-SHA256-FINGERPRINT'
```

The script compares the returned bundle with the CSR and request metadata retained locally, checks the CSR-to-certificate public key, verifies the strict certificate chain and Root CRL, and requires the Root fingerprint recorded independently during Root initialization. It then verifies that the Issuing private key matches the signed certificate, creates an initial Issuing CRL, and prepares publication files.

### 5. Publish CA certificate and CRL files

Publish the binary files from:

```text
D:\PrivatePKI\IssuingCA\publish
```

At minimum, confirm that these URLs return the exact local files:

```text
https://pki.your-domain.example/document-signing/root-ca.cer
https://pki.your-domain.example/document-signing/root-ca.crl
https://pki.your-domain.example/document-signing/issuing-ca.cer
https://pki.your-domain.example/document-signing/issuing-ca.crl
```

Do not require authentication, cookies, redirection through a login page, or JavaScript to download these files.

## Issue an individual document-signing certificate

Run on the **Issuing CA computer** after identity verification and documented approval:

```powershell
& 'C:\PKI-Tools\PrivateDocumentPki.ps1' IssueDocumentSigner `
  -OpenSslPath 'C:\Program Files\OpenSSL-Win64\bin\openssl.exe' `
  -IssuingCaPath 'D:\PrivatePKI\IssuingCA' `
  -IssuedPath 'D:\PrivatePKI\Issued' `
  -SignerCommonName 'FULL LEGAL NAME, CREDENTIALS' `
  -SignerEmail 'signer@your-domain.example' `
  -SignerTitle 'AUTHORIZED SIGNER TITLE' `
  -SignerOrganization 'YOUR EXACT LEGAL ORGANIZATION NAME'
```

The output package contains:

```text
private\<signer>.key.pem          Encrypted software private key
csr\<signer>.csr.pem              CSR
certs\<signer>.cert.pem           PEM signer certificate
certs\<signer>.cer                DER signer certificate
certs\<signer>-fullchain.cert.pem Signer + Issuing + Root chain
pfx\<signer>.pfx                  Windows/Acrobat/Office import package
certificate-metadata.json         Issuance details
SHA256SUMS.txt                     Integrity manifest
```

Every human signer must receive a **separate certificate and private key**. Never share a PFX, private-key password, token PIN, or cloud-signing account.

## Verify a signer certificate

```powershell
& 'C:\PKI-Tools\PrivateDocumentPki.ps1' VerifyDocumentSigner `
  -OpenSslPath 'C:\Program Files\OpenSSL-Win64\bin\openssl.exe' `
  -IssuingCaPath 'D:\PrivatePKI\IssuingCA' `
  -CertificatePath 'D:\PrivatePKI\Issued\<PACKAGE>\certs\<SIGNER>.cert.pem'
```

This performs strict chain validation and, when both CRLs are available, revocation validation for the full chain. It then prints the subject, issuer, serial, validity, fingerprint, key usage, EKUs, SAN, AIA, and CRL distribution points.

## Install private trust on a Windows computer

Run on each managed relying computer, preferably through Group Policy/Intune rather than manually:

```powershell
& 'C:\PKI-Tools\PrivateDocumentPki.ps1' InstallTrust `
  -OpenSslPath 'C:\Program Files\OpenSSL-Win64\bin\openssl.exe' `
  -IssuingCaPath 'D:\PrivatePKI\IssuingCA' `
  -TrustScope 'LocalMachine' `
  -ExpectedRootFingerprint 'REPLACE-WITH-64-HEX-SHA256-FINGERPRINT'
```

`LocalMachine` requires an elevated PowerShell session. `CurrentUser` does not require elevation but trusts the CA only for that user profile. The command refuses to install trust unless the supplied Root SHA-256 fingerprint matches the certificate being installed.

Installing trust in Windows does not guarantee that every Acrobat configuration will trust the private Root CA. Validate Acrobat trust settings on a clean, managed workstation.

## Install the signer PFX

Run while signed in as the actual signer:

```powershell
& 'C:\PKI-Tools\PrivateDocumentPki.ps1' InstallSignerPfx `
  -OpenSslPath 'C:\Program Files\OpenSSL-Win64\bin\openssl.exe' `
  -PfxPath 'D:\PrivatePKI\Issued\<PACKAGE>\pfx\<SIGNER>.pfx'
```

The script imports the private key into `Cert:\CurrentUser\My` without enabling export. After successful import and testing, move the PFX into an approved encrypted backup vault or destroy the working copy according to the key-management policy.

## Sign a PDF in Adobe Acrobat or Acrobat Reader

1. Finalize the PDF and retain the controlled unsigned source.
2. Open the final PDF.
3. Select **All tools → Use a certificate → Digitally sign**.
4. Draw or select the signature field.
5. Select the named document-signing certificate.
6. Enter the certificate PIN/password when prompted.
7. Choose the signature reason/meaning required by your procedure.
8. Apply a trusted timestamp when configured.
9. Save as a new, controlled signed file.
10. Open the Signatures panel and confirm the signature and chain status.

Do not use only a typed or pasted signature image when a certificate-based digital signature is required.

## Sign a Word document

After the PFX is installed in the actual signer's Current User certificate store:

- use **Insert → Signature Line**, then sign the line; or
- use **File → Info → Protect Document → Add a Digital Signature**.

A change to the document after signing invalidates the signature. For external distribution, the more interoperable workflow is often to finalize the DOCX, export a PDF, review the PDF, and digitally sign the PDF.

## Generate current CRLs

Root CRL, on the offline Root CA:

```powershell
& 'E:\PKI-Tools\PrivateDocumentPki.ps1' GenerateRootCrl `
  -OpenSslPath 'C:\Program Files\OpenSSL-Win64\bin\openssl.exe' `
  -RootCaPath 'E:\PrivatePKI\RootCA'
```

Issuing CRL, on the Issuing CA computer:

```powershell
& 'C:\PKI-Tools\PrivateDocumentPki.ps1' GenerateIssuingCrl `
  -OpenSslPath 'C:\Program Files\OpenSSL-Win64\bin\openssl.exe' `
  -IssuingCaPath 'D:\PrivatePKI\IssuingCA'
```

Publish the updated `.crl` file immediately. Do not allow a CRL to expire. The default Issuing CRL lifetime is seven days, so the operating procedure must generate and publish it well before that deadline.

## Revoke a signer certificate

```powershell
& 'C:\PKI-Tools\PrivateDocumentPki.ps1' RevokeDocumentSigner `
  -OpenSslPath 'C:\Program Files\OpenSSL-Win64\bin\openssl.exe' `
  -IssuingCaPath 'D:\PrivatePKI\IssuingCA' `
  -CertificatePath 'D:\PrivatePKI\Issued\<PACKAGE>\certs\<SIGNER>.cert.pem' `
  -RevocationReason 'keyCompromise'
```

The script updates the CA database, creates a new Issuing CRL, and instructs the operator to publish it. Do not merely delete a certificate or PFX; deletion does not communicate revocation to relying parties.

## Revoke the Issuing CA

Use only for a documented CA compromise or decommissioning event, on the offline Root CA:

```powershell
& 'E:\PKI-Tools\PrivateDocumentPki.ps1' RevokeIssuingCA `
  -OpenSslPath 'C:\Program Files\OpenSSL-Win64\bin\openssl.exe' `
  -RootCaPath 'E:\PrivatePKI\RootCA' `
  -CertificatePath 'E:\PrivatePKI\RootCA\certs\issuing-ca.cert.pem' `
  -RevocationReason 'CACompromise'
```

Immediately stop all issuance from that CA, publish the new Root CRL, activate the incident-response plan, and replace the Issuing CA.

## Timestamping

The package does not create a public trusted timestamp authority. Configure Adobe/Word or your signing library to use an approved RFC 3161 timestamp service. A private timestamp server is trusted only where its trust chain is deployed. Timestamping must be tested as part of the final signing workflow, not merely assumed because a certificate exists.

## Operational safeguards implemented by the script

- separate Root and Issuing CA workflows;
- CA path-length constraints;
- controlled certificate extensions rather than copying extensions from untrusted CSRs;
- encrypted private keys and PFX;
- passphrases kept out of process command lines through restricted temporary files;
- best-effort deletion of temporary secret files;
- Windows ACL hardening for CA and signer directories;
- random positive serial-number seeds;
- CA database backups before each mutating OpenSSL CA command;
- exclusive file locks around CA database operations;
- strict chain validation;
- key/certificate pair verification;
- CRL generation and CRL-aware verification;
- transfer-bundle and signer-package SHA-256 manifests;
- mandatory manifest coverage of every required transfer file, with duplicate-entry and path-escape rejection;
- Root-CRL currency and Issuing-CA revocation checks before signer issuance or Windows trust installation;
- high-impact PowerShell confirmation prompts;
- refusal to initialize a non-empty CA directory;
- policy maximums for signer validity;
- operational JSON Lines audit records.

## Important limitations

This package is not, by itself:

- an AATL/publicly trusted certificate service;
- identity proofing or certificate-policy governance;
- an HSM-backed CA;
- an OCSP responder;
- a trusted timestamp authority;
- a tamper-proof regulatory audit-trail system;
- a 21 CFR Part 11-compliant electronic-record system;
- a PDF/DOCX signature engine; or
- a replacement for Adobe Sign workflows involving remote recipients, routing, reminders, authentication, or platform audit reports.

Before production use, complete the security and operations checklist and validate the entire workflow on non-production Windows devices and clean recipient devices.
