# Phishing Triage Checklist

## 1. Pause
- Do not click links, scan QR codes, open unexpected attachments, or call numbers from the message.
- Look for Authority, Urgency, Curiosity, Fear/Greed triggers.

## 2. Verify
### Sender/Header checks
- Compare the display name with the real From address.
- Inspect From and Return-Path where available.
- Check for lookalike, typosquatted, homoglyph, combosquatted, or nested-subdomain domains.
- Read domains from right to left to identify the true root domain.

### Content checks
- Look for requests for passwords, MFA codes, payment details, or wire transfers.
- Look for secrecy or instructions to bypass normal security/procurement procedures.
- Watch for unusual sign-in alerts that push a direct login link.
- Inspect forwarded chains for odd timestamps or pasted headers.
- Treat .iso, .js, .scr and unexpected HTML attachments as high risk.
- Treat unsolicited QR codes and callback phone numbers as phishing indicators.
- Be alert to requests supported by voice/video impersonation.

## 3. Report
- Safe -> Close after normal checks.
- Suspicious -> Warn the user and verify through a trusted channel.
- Malicious -> Block the domain/message and escalate to the security team.

## Golden rule
**PAUSE -> VERIFY -> REPORT**

Never use the contact details or links supplied by a suspicious message to perform the verification.
