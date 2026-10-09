# Security and Operations Checklist for a Private Document-Signing PKI

The technical scripts are only one part of a trustworthy document-signing program. Complete and approve this checklist before production use.

## 1. Governance and intended use

- [ ] Define the exact document types that may be signed with this private PKI.
- [ ] Define document types that must remain in Adobe Sign, a sponsor portal, an EDC/eSource system, an eConsent system, or another validated platform.
- [ ] Approve a Certificate Policy (CP) and Certificate Practice Statement (CPS), even if concise.
- [ ] Name the PKI owner, Root CA custodians, Issuing CA operators, security owner, compliance owner, and backup custodians.
- [ ] Define who may approve certificate issuance, renewal, suspension, revocation, and CA rollover.
- [ ] Define a relying-party agreement and communicate that this is a private trust model.
- [ ] Define retention periods for CA databases, requests, certificates, CRLs, approval evidence, and signed documents.
- [ ] Confirm legal, regulatory, sponsor/CRO, IRB, contract, and records-management requirements for each document class.

## 2. Identity proofing and signer authorization

- [ ] Verify each signer's legal identity using an approved process before issuance.
- [ ] Verify professional credentials and organizational role where included in the certificate subject.
- [ ] Verify the signer's email address and employment/affiliation.
- [ ] Record the identity-proofing method, evidence reference, reviewer, and date.
- [ ] Obtain documented approval from an authorized certificate approver.
- [ ] Issue one unique certificate and private key per individual.
- [ ] Prohibit shared PFX files, shared token PINs, shared cloud-signing accounts, or signing on behalf of another person.
- [ ] Define immediate revocation triggers for termination, role change, credential loss, compromise, or suspected misuse.

## 3. Root CA ceremony

- [ ] Use a dedicated, hardened, offline Root CA computer or approved offline boot environment.
- [ ] Record hardware identifiers, operating-system build, OpenSSL build and hash, script hash, date, participants, and purpose.
- [ ] Require at least two authorized people for Root CA ceremonies when organizational risk warrants dual control.
- [ ] Disable or remove ordinary network connectivity.
- [ ] Use approved encrypted removable media for inbound CSRs and outbound signed bundles.
- [ ] Malware-scan transfer media on a separate controlled system before and after transfer.
- [ ] Review the Issuing CA CSR subject and approved request metadata before signing.
- [ ] Verify the Root certificate SHA-256 fingerprint through an independent channel before trust deployment.
- [ ] During Issuing CA finalization, compare the returned CSR with the CSR retained locally and verify that the signed certificate contains the same public key.
- [ ] Require the independently recorded Root SHA-256 fingerprint during Issuing CA finalization and every manual trust installation.
- [ ] Store the Root passphrase under split knowledge or an equivalent approved control.
- [ ] Seal and inventory Root CA backups and recovery media.
- [ ] Return the Root CA to offline storage immediately after the ceremony.

## 4. Key protection

- [ ] Use an approved HSM, hardware token, or cloud HSM for production signer and Issuing CA keys where feasible.
- [ ] Treat the supplied software-key workflow as a reference or lower-assurance deployment, not as equivalent to an HSM.
- [ ] Use passphrases of at least 20 printable ASCII characters; longer random passphrases are preferred.
- [ ] Store passphrases in an approved enterprise password vault with access logging and MFA.
- [ ] Do not store passwords in scripts, command lines, tickets, email, chat, source control, logs, or environment variables.
- [ ] Restrict CA and signer directories to the intended operator, SYSTEM, and approved administrators.
- [ ] Use full-disk encryption on CA workstations and encrypted removable media.
- [ ] After importing a PFX, keep the Windows private key non-exportable when operationally possible.
- [ ] Destroy working PFX copies after approved backup and successful import validation.
- [ ] Document that best-effort file overwrite is not guaranteed secure erasure on SSDs; use cryptographic erasure or approved media destruction when required.

## 5. CA host hardening

- [ ] Use a dedicated Issuing CA host or tightly controlled administrative workstation.
- [ ] Apply current supported OS security updates under change control.
- [ ] Use application allowlisting and endpoint protection compatible with CA operations.
- [ ] Enforce phishing-resistant MFA for administrative access where supported.
- [ ] Deny routine internet browsing, email, office productivity use, and ordinary user activity on CA systems.
- [ ] Limit local administrators and perform periodic access reviews.
- [ ] Enable secure boot, TPM protection, disk encryption, and BIOS/UEFI passwords where appropriate.
- [ ] Send security logs to a protected central logging system without copying private keys or passwords.
- [ ] Monitor for unauthorized CA directory changes and unexpected certificate issuance.

## 6. CA database integrity and concurrency

- [ ] Keep one authoritative copy of each CA database.
- [ ] Do not synchronize an active OpenSSL CA database with consumer file-sync tools.
- [ ] Do not run simultaneous CA issuance, revocation, or CRL commands.
- [ ] Retain the script's pre-operation database backups.
- [ ] Back up `index.txt`, `index.txt.attr`, `serial`, `crlnumber`, `newcerts`, certificates, CRLs, configuration, metadata, and audit records.
- [ ] Test recovery in a non-production environment before relying on the backup plan.
- [ ] Reconcile CA database entries, issued certificate files, approvals, and signer inventory periodically.

## 7. Certificate and CRL publication

- [ ] Use a stable PKI publication hostname and path before issuing certificates.
- [ ] Publish `root-ca.cer`, `root-ca.crl`, `issuing-ca.cer`, and `issuing-ca.crl` at the exact embedded URLs.
- [ ] Make files available without authentication, cookies, browser scripting, or login redirects.
- [ ] Serve the correct binary content; do not replace certificate or CRL files with HTML error pages.
- [ ] Monitor HTTP status, content hash, CRL issuer, CRL number, `thisUpdate`, and `nextUpdate`.
- [ ] Generate and publish the Issuing CRL well before its seven-day default expiration.
- [ ] Generate and publish the Root CRL well before its 365-day default expiration.
- [ ] Create alerts sufficiently in advance to recover from operator absence or publication failure.
- [ ] Publish a fresh CRL immediately after revocation.
- [ ] Retain prior CRLs according to policy while ensuring the URL presents the current CRL.

## 8. Trust deployment

- [ ] Deploy only the verified Root CA certificate to the Trusted Root store.
- [ ] Deploy the Issuing CA certificate to the Intermediate Certification Authorities store.
- [ ] Verify the Root fingerprint out of band before deployment.
- [ ] Prefer Group Policy, Intune, MDM, or a configuration-management platform over manual installation.
- [ ] Restrict who may add trusted roots on managed computers.
- [ ] Test Acrobat's trust behavior separately from Windows trust behavior.
- [ ] Test Word signature validation on a clean managed workstation.
- [ ] Test an unmanaged external recipient scenario and document the expected untrusted/private-CA warning.
- [ ] Never tell external recipients that the private certificate is AATL/publicly trusted.

## 9. Signing workflow

- [ ] Finalize and review the exact document version before signing.
- [ ] Retain the controlled source and final rendered file according to procedure.
- [ ] Capture or associate the signer's identity, signature meaning, date/time, exact record version, and record hash.
- [ ] Require authentication or step-up authentication at the time of signing.
- [ ] Apply a trusted RFC 3161 timestamp when the use case requires long-term validation.
- [ ] Verify the completed signature, certificate chain, timestamp, and revocation status.
- [ ] Prevent silent changes to signed documents.
- [ ] Create a new version and obtain a new signature when a signed record changes.
- [ ] Do not copy a visible signature image from one document to another.
- [ ] Do not let assistants or coordinators use another person's private key or token.

## 10. PDF and DOCX validation

- [ ] Use certificate-based signing, not only a typed/drawn image.
- [ ] Verify a signed PDF in Adobe Acrobat/Reader on a clean computer.
- [ ] Confirm that the PDF signature covers the expected byte ranges and that post-signing changes are reported.
- [ ] Confirm whether the document is approval-signed, certification-signed, or locked, as required.
- [ ] Verify DOCX signatures in a supported desktop version of Microsoft Word.
- [ ] Confirm the signer certificate appears as intended in Acrobat and Word before broad deployment.
- [ ] Test multiple-signature workflows and document locking behavior before production use.
- [ ] Test long-term validation after the signer certificate has expired in a controlled test environment.

## 11. Timestamp service

- [ ] Select an approved RFC 3161 timestamp authority.
- [ ] Confirm whether the timestamp chain is trusted by intended recipients.
- [ ] Configure the timestamp server in Acrobat, Word, or the signing library.
- [ ] Protect timestamp credentials and API keys.
- [ ] Monitor timestamp service availability and certificate expiration.
- [ ] Validate that the timestamp is embedded in the final signature, not merely displayed from the local clock.
- [ ] Define fallback behavior; do not silently sign without a required timestamp.

## 12. Revocation and incident response

- [ ] Maintain a 24/7 or clearly defined reporting method for lost tokens, exposed PFX files, suspected compromise, and unauthorized signatures.
- [ ] Define revocation-reason selection rules.
- [ ] Revoke compromised signer certificates promptly.
- [ ] Publish and verify the new CRL immediately.
- [ ] Notify relying parties when required.
- [ ] Preserve evidence and signed documents for investigation.
- [ ] Define procedures for an Issuing CA compromise, including Root-level revocation and replacement.
- [ ] Define procedures for a Root CA compromise, including trust removal, legal/compliance notification, and complete PKI replacement.
- [ ] Conduct and document post-incident review.

## 13. Renewal and rollover

- [ ] Alert at least 180, 120, 90, 60, and 30 days before CA certificate expiration.
- [ ] Alert at least 90, 60, and 30 days before signer certificate expiration.
- [ ] Ensure a child certificate never extends beyond its issuer's validity.
- [ ] Plan Issuing CA rollover before the remaining lifetime is too short for normal signer issuance.
- [ ] Plan Root CA rollover years in advance because trust deployment takes time.
- [ ] Decide whether renewal reuses a key or generates a new key; new keys are generally preferred for high-assurance rollover.
- [ ] Maintain old chains and CRLs for validation of historical signatures.
- [ ] Test historical signature validation during rollover.

## 14. Backup, recovery, and disaster recovery

- [ ] Keep at least two encrypted, geographically separated Root CA backups under controlled custody.
- [ ] Keep encrypted Issuing CA backups consistent with the active CA database.
- [ ] Protect backup keys at least as strongly as production keys.
- [ ] Record backup creation, verification, custody, transfer, restore test, and destruction.
- [ ] Perform periodic restoration to an isolated non-production environment.
- [ ] Verify that restored CA state cannot issue duplicate serials or lose revocation history.
- [ ] Define recovery point and recovery time objectives.

## 15. Audit and evidence

- [ ] Forward or preserve the script's JSON Lines operational records in a tamper-evident or immutable repository.
- [ ] Record certificate request, identity proofing, approval, issuance, delivery, acceptance, renewal, revocation, and destruction events.
- [ ] Record software versions, script hashes, configuration hashes, and operator identities for each ceremony.
- [ ] Retain certificate and CRL fingerprints and serial numbers.
- [ ] Periodically reconcile the signer inventory against active staff and authorized roles.
- [ ] Review privileged access and CA operations at a defined frequency.
- [ ] Treat local text logs as operational evidence, not automatically as a validated regulatory audit trail.

## 16. Clinical-research and regulated-record controls

- [ ] Perform a documented intended-use and regulatory applicability assessment.
- [ ] Determine whether the official record belongs in a sponsor/CRO/IRB/EDC/eSource/eConsent system rather than a locally signed file.
- [ ] Validate the complete electronic-record system, not merely the certificate-generation script, where required.
- [ ] Ensure the signature is permanently linked to the exact signed record version.
- [ ] Preserve signer name, meaning, date/time, record identifier, record hash, authentication evidence, and reason/intent.
- [ ] Ensure changes create a new version and trigger re-signature when applicable.
- [ ] Maintain access controls, audit trails, retention, retrieval, accurate copies, and change control.
- [ ] Confirm sponsor/CRO acceptance before substituting a private certificate workflow for a required platform.
- [ ] Ensure PHI-bearing files remain in approved encrypted storage and are not exposed through publication endpoints.

## 17. Go-live acceptance tests

- [ ] Root self-signature validates with strict OpenSSL verification.
- [ ] Issuing CA validates to the Root with `pathLen:0`.
- [ ] Signer validates to the Issuing CA and Root.
- [ ] Signer certificate is `CA:false` and contains only the approved document-signing uses.
- [ ] The signer private key matches the signer certificate.
- [ ] The PFX opens with the expected password and algorithms.
- [ ] The Root and Issuing CRLs validate and are not expired.
- [ ] A revoked test signer fails CRL-aware verification.
- [ ] Publication URLs return files with the expected hashes.
- [ ] Windows, Acrobat, and Word trust behavior matches the documented trust model.
- [ ] A signed PDF detects an intentional post-signing modification.
- [ ] A signed DOCX detects an intentional post-signing modification.
- [ ] Timestamp validation works from a clean relying computer.
- [ ] Backup restoration and historical signature validation have been demonstrated.
- [ ] All limitations and residual risks have written approval.
