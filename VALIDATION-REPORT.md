# Validation Report — Private Document-Signing PKI Package

## 1. Scope

This report records the verification performed on the supplied private document-signing PKI reference implementation. It covers:

- the OpenSSL certificate and CRL profile;
- Root, Issuing CA, and document-signer chain construction;
- PKCS#12/PFX packaging;
- revocation behavior;
- package integrity and static checks; and
- known validation limitations.

This is engineering verification, not an independent security assessment, a certificate-policy audit, an AATL approval, an eIDAS qualification, or a 21 CFR Part 11 validation determination.

## 2. Test environment

| Item | Value |
|---|---|
| Test date | 2026-10-09 |
| OpenSSL | OpenSSL 3.5.5, 27 January 2026 |
| Platform | Debian Linux, x86-64 |
| PowerShell runtime | Not available in this build environment |
| Test identities | Synthetic test identities only |

No production private key, password, certificate, CRL, PFX, PHI, or real signer identity is included in the deliverable.

## 3. Cryptographic lifecycle test

A complete synthetic two-tier lifecycle was executed with the same hierarchy, key sizes, signature algorithms, X.509 constraints, signer EKUs, PFX protection settings, and revocation model used by the package. Test certificate lifetimes were intentionally shorter than the default production-oriented values; this does not change the extension, chain, key, PFX, or revocation behavior being tested.

### 3.1 Root CA

Result: **Passed**

Verified:

- RSA 4096-bit private key;
- encrypted private-key generation and `openssl pkey -check`;
- SHA-384 certificate signature;
- self-issued and self-signed Root certificate;
- strict self-signature validation using `openssl verify -x509_strict -check_ss_sig`;
- critical `basicConstraints = CA:TRUE, pathlen:1`;
- critical `keyUsage = keyCertSign, cRLSign`;
- Subject Key Identifier and Authority Key Identifier; and
- Root CRL generation and parsing.

### 3.2 Issuing CA

Result: **Passed**

Verified:

- RSA 4096-bit private key;
- encrypted private-key generation and key check;
- CSR signature verification;
- SHA-384 certificate signature by the Root CA;
- strict Root-to-Issuing chain validation;
- critical `basicConstraints = CA:TRUE, pathlen:0`;
- critical `keyUsage = keyCertSign, cRLSign`;
- AIA CA Issuers URL;
- Root CRL Distribution Point; and
- Issuing CA CRL generation and parsing.

### 3.3 Document signer

Result: **Passed**

Verified:

- RSA 3072-bit private key;
- encrypted private-key generation and key check;
- CSR signature verification;
- SHA-256 signer-certificate signature by the Issuing CA;
- private-key/public-certificate match;
- strict Root-to-Issuing-to-signer chain validation;
- critical `basicConstraints = CA:FALSE`;
- critical `keyUsage = digitalSignature, nonRepudiation`;
- IETF document-signing EKU `1.3.6.1.5.5.7.3.36`;
- Microsoft Office document-signing EKU `1.3.6.1.4.1.311.10.3.12`;
- Adobe document-signing compatibility OID `1.2.840.113583.1.1.5`;
- RFC 822 email Subject Alternative Name;
- Issuing CA AIA URL; and
- Issuing CA CRL Distribution Point.

### 3.4 PKCS#12/PFX

Result: **Passed**

`openssl pkcs12 -info -noout` confirmed:

```text
MAC: sha256, Iteration 200000
MAC length: 32, salt length: 16
PKCS7 Encrypted data: PBES2, PBKDF2, AES-256-CBC, Iteration 200000, PRF hmacWithSHA256
Certificate bag
Certificate bag
Certificate bag
PKCS7 Data
Shrouded Keybag: PBES2, PBKDF2, AES-256-CBC, Iteration 200000, PRF hmacWithSHA256
```

The three certificate bags represented the signer, Issuing CA, and Root CA certificates. No private material from the test is included in this package.

### 3.5 CRL-aware verification and revocation

Result: **Passed**

Before revocation, `openssl verify -x509_strict -crl_check_all` succeeded with both CA CRLs.

After the signer certificate was revoked for `keyCompromise` and a fresh Issuing CA CRL was generated, the same verification correctly failed with:

```text
error 23 at 0 depth lookup: certificate revoked
verification failed
```

This is the required negative test: a revoked signer must no longer validate when the relying party has the current CRLs.

## 4. Transfer and trust hardening review

The final script requires all of the following before an Issuing CA can be finalized:

- signed-bundle SHA-256 manifest verification with mandatory coverage of every required file;
- rejection of duplicate manifest entries, absolute paths, and bundle-directory path escapes;
- comparison of returned metadata with the Issuing CA request metadata retained locally;
- byte-for-byte SHA-256 comparison of the returned CSR with the locally retained CSR;
- CSR signature verification;
- CSR public-key comparison with the issued certificate public key;
- exact CSR/certificate subject comparison;
- strict Issuing CA chain verification;
- Root CRL signature, currency, and Issuing-CA revocation verification;
- signed-bundle Root and Issuing certificate fingerprint checks; and
- comparison of the Root certificate with an independently recorded SHA-256 fingerprint supplied through `-ExpectedRootFingerprint`.

The same independently recorded Root fingerprint is mandatory for the `InstallTrust` action.

## 5. Static package validation

Result: **Passed**

Automated static checks confirmed:

- balanced PowerShell braces, brackets, parentheses, comments, quoted strings, and here-strings;
- no duplicate PowerShell function names;
- no duplicate keys in ordered object literals detected by the package checker;
- matching action declarations between `PrivateDocumentPki.ps1` and `Example-Commands.ps1`;
- mandatory Root-CRL preflight checks before signer issuance and trust installation;
- balanced Markdown code fences;
- no private-key PEM blocks;
- no generated certificate or CRL PEM blocks;
- no embedded PFX files;
- no production passwords or passphrases; and
- no trailing whitespace or tab characters in the PowerShell and Markdown files.

The package contains only scripts, documentation, configuration examples, and integrity hashes.

## 6. Validation limitations

### 6.1 Windows PowerShell execution

A Windows or PowerShell runtime was not available in the build container. The PowerShell source was statically checked, but the complete `.ps1` workflow was **not executed on Windows in this environment**. Before any production key ceremony, execute the entire workflow with synthetic names on the exact intended Windows version and exact vetted OpenSSL build.

At minimum, the Windows qualification run must cover:

1. `InitializeRoot`;
2. `CreateIssuingRequest`;
3. `SignIssuingRequest`;
4. `FinalizeIssuing` with the independently recorded Root fingerprint;
5. `IssueDocumentSigner`;
6. `VerifyDocumentSigner` before revocation;
7. PFX import into `Cert:\CurrentUser\My`;
8. Windows chain building and revocation behavior;
9. PDF signing and validation in the deployed Acrobat/Reader version;
10. DOCX signing and validation in the deployed Microsoft Word version;
11. signer revocation and fresh-CRL publication; and
12. failed validation of the revoked signer on a clean relying workstation.

### 6.2 Application-level signing

The package creates certificates and PFX files. It does not itself create PAdES signatures in PDFs or OPC digital signatures in DOCX files. Acrobat/Reader, Microsoft Word, or a separately validated signing component must be tested in the actual operating environment.

### 6.3 Public trust

The test establishes cryptographic validity inside the private trust model. It does not make the Root CA publicly trusted, place it on Adobe's Approved Trust List, enroll it in a Microsoft root program, or qualify it under eIDAS.

### 6.4 Hardware-protected keys

The included reference implementation generates software-protected encrypted keys. HSM, smart-card, USB-token, TPM, and cloud-HSM integrations require vendor-specific providers or PKCS#11 modules and separate qualification.

### 6.5 Regulatory use

A valid certificate signature is only one technical control. Regulated use also requires approved procedures, identity proofing, access control, signature intent, exact record/version linkage, audit trails, retention, training, validation evidence, incident handling, and operating controls.

## 7. Production-release gate

Do not authorize production use until the organization has approved:

- certificate policy and certification-practice documents;
- identity-proofing and signer-authorization procedures;
- offline Root ceremony and dual-control procedures;
- HSM/token decision and key-custody model;
- CRL generation, publication, monitoring, and emergency revocation procedures;
- backup, restore, disaster-recovery, and destruction tests;
- trusted timestamping design;
- Windows, Acrobat, Word, and recipient interoperability qualification;
- security review and penetration testing appropriate to the deployment;
- regulated-system validation and traceability, where applicable; and
- a formal production approval record.
