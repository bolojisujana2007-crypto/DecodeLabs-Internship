# Project 3 — Phishing Awareness Analysis

This submission analyzes sample emails/messages for phishing indicators and provides a practical triage toolkit.

## Files
- `Phishing_Awareness_Analysis_Report.pdf` — polished project report
- `phishing_analysis.csv` — structured analysis dataset
- `phishing_triage_checklist.md` — non-expert red-flag checklist
- `phishing_triage_decision_tree.md` — triage decision tree and outcomes
- `requirements_verification.txt` — requirement-by-requirement quality check

## Coverage
The analysis explicitly identifies:
1. Suspicious links/domains and keywords
2. Red flags
3. Why each message is unsafe
4. Threat-analysis and security-thinking actions

The report also covers sender/header anomalies, lookalike and nested domains, urgency/authority triggers, dangerous attachments, MFA/password requests, callback phishing, QR phishing, fake forwarded chains, and multi-channel impersonation.

## Safety note
All examples are defensive training samples. Do not click, scan, open, or call suspicious content; verify through a trusted independent channel.

## Running the Python analyzer

Open Command Prompt/Terminal in the extracted project folder:

    python phishing_analyzer.py

One-line test:

    python phishing_analyzer.py --text "Your account will be disabled today. Sign in immediately at https://example.com/login"

This is a defensive training analyzer using simple rules for URLs, phishing keywords, urgency, credential/payment requests, secrecy, threats, impersonation language, and risky attachment extensions.
