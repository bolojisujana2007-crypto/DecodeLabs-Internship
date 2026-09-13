# Project 4: Audited Systems — Blue Team Defense

## Purpose
This kit implements the **4-step workstation security audit** described in the provided DecodeLabs Project 4 training deck. The goal is to establish a baseline, inspect the system methodically, risk-rank findings, and produce evidence for a hardened state.

> **Important:** Run the audit on your own primary computer. The included sample report is illustrative; do not submit it as personal-machine evidence without running the tool and replacing the sample values with your actual results.

## Checklist implemented
1. **Identity Front Door** — password/passphrase and MFA review; guest-account and privilege checks.
2. **Software Decay & Patch Management** — operating-system update evidence and patch observations.
3. **Auditing the Human Perimeter** — guest account, privilege creep, screen-lock/credential/USB/social-engineering items requiring manual verification.
4. **Network & Endpoint Hygiene** — firewall and local-disk encryption checks.

The deck also presents an execution matrix for Windows PowerShell and macOS Terminal, CVSS-style risk categories, and a one-page vulnerability report containing diagnosis, remediation, and hardened verification.

## Files
- `src/audit_system.py` — read-only cross-platform audit script.
- `reports/vulnerability_report.md` — one-page report template matching the required Diagnosis → Treatment → Proof structure.
- `reports/sample_vulnerability_report.md` — illustrative example only.
- `docs/audit_checklist.md` — detailed checklist and evidence collection guide.
- `docs/execution_matrix.md` — Windows/macOS CLI matrix aligned to the deck.
- `outputs/audit_results.json` — generated machine-readable audit output placeholder; overwrite it by running the script.

## Requirements
- Python 3.9+ recommended.
- Windows, macOS, or Linux.
- Some checks may need an **Administrator/root** terminal for complete visibility. The script does not change settings.
- No third-party Python packages are required.

## Run in VS Code / terminal
From the project folder:

```text
python src/audit_system.py
```

To choose an output file:

```text
python src/audit_system.py --output outputs/audit_results.json
```

On systems where `python` is not the command, try `py` (Windows) or `python3` (macOS/Linux).

## What to submit
After running the script on your primary computer:
1. Keep `outputs/audit_results.json` as raw evidence.
2. Fill `reports/vulnerability_report.md` with at least **three specific findings** actually supported by your evidence.
3. For each finding include severity/CVSS rationale, exact remediation action, and a verification result after remediation.
4. Add terminal screenshots if your trainer requires visual proof.

## Safety and scope
This is a defensive, local audit. It does not scan other computers, exploit vulnerabilities, brute-force credentials, or modify security settings. It only collects local configuration evidence and reports items that need attention.
