# Audited Systems — 4-Step Checklist

## Step 1 — The Identity Front Door
### Passwords
- Prefer strong, memorable passphrases.
- Review account policy and avoid unnecessary password practices that create predictable reuse.

### MFA
- Prefer phishing-resistant authenticators such as FIDO2/WebAuthn or passkeys for important accounts.
- Record which important accounts have MFA enabled.

### Local identity checks
- Confirm the Guest account is disabled unless there is a documented need.
- Review administrator/sudo membership for privilege creep.
- Record evidence without exposing passwords, recovery codes, or secrets.

## Step 2 — Software Decay & Patch Management
- Verify automated operating-system updates are enforced where appropriate.
- Identify pending OS updates.
- Review browser and antivirus/endpoint-protection freshness.
- Identify unapproved or unnecessary applications (Shadow IT).
- Treat delayed security updates as accepted risk until remediated.

## Step 3 — Auditing the Human Perimeter
### System misconfigurations
- Guest account threat: unnecessary guest access increases attack surface.
- Privilege creep: remove unchecked or lingering admin access.

### Physical & behavioral hygiene
- Verify screen-lock timeout.
- Check for credentials stored on sticky notes or in unencrypted files.
- Review removable/rogue USB devices.
- For suspicious calls/messages, verify through a secondary trusted communication channel.
- Consider deepfakes/cloned voices as a social-engineering risk.

## Step 4 — Network & Endpoint Hygiene
### The Shield — inbound traffic controls
- Verify the OS firewall is active.
- Review inbound rules for unnecessary exposure.
- On macOS, verify Application Firewall state and consider Stealth Mode as appropriate.

### The Vault — data at rest
- Verify local disk encryption.
- Windows: BitLocker/TPM status.
- macOS: FileVault status.
- Linux: confirm an appropriate full-disk encryption design such as LUKS where applicable.

## Risk funnel
Use four practical categories:
- **Critical:** immediate action; examples include severe remotely exploitable exposure or unprotected sensitive data.
- **High:** urgent remediation; examples include disabled firewall, unpatched security software, or weak privileged-account protection.
- **Medium:** planned remediation; examples include permissive local settings or missing hardening controls.
- **Low:** hygiene improvements with limited immediate impact.

For formal scoring, use the official CVSS calculator rather than inventing a score. The sample values in this kit are only triage examples.
