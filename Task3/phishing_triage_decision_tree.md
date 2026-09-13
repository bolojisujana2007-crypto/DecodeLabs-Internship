# Phishing Triage Decision Tree

Incoming suspicious email/message
|
+-- Does it request credentials, MFA codes, payment, secrecy, or bypass of procedure?
|      +-- YES -> Suspicious/Malicious -> Verify independently
|      +-- NO  -> Continue
|
+-- Is the sender/domain inconsistent, lookalike, nested, or otherwise suspicious?
|      +-- YES -> Suspicious/Malicious -> Inspect headers and URL
|      +-- NO  -> Continue
|
+-- Does it use urgency, authority, fear/greed, curiosity, or an unusual call/QR action?
|      +-- YES -> Suspicious -> Do not interact; verify independently
|      +-- NO  -> Continue
|
+-- Does it contain an unexpected risky attachment or direct login link?
|      +-- YES -> Suspicious/Malicious -> Isolate and escalate
|      +-- NO  -> Safe candidate -> Complete normal verification

## Required outcome
- SAFE -> Close
- SUSPICIOUS -> Warn User
- MALICIOUS -> Block Domain & Escalate
