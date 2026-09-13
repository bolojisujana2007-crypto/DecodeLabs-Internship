#!/usr/bin/env python3
"""Project 3 - Phishing Awareness Analyzer (defensive training tool)."""
import argparse, re

RULES = {
    "urgency": ["urgent","immediately","act now","today","within 30 minutes","before close","right away","expires","last chance"],
    "credential_request": ["password","passcode","mfa code","otp","verification code","confirm your credentials","login","sign in"],
    "financial_request": ["wire transfer","payment","invoice","bank details","gift card","approve the payment","payment failed","refund"],
    "secrecy": ["strictly confidential","do not discuss","keep this confidential","don't tell anyone"],
    "threat": ["disabled","locked","suspended","prevent your account","security alert","suspicious login","unusual sign-in"],
    "social_engineering": ["ceo","executive","it security","account security","security team","manager","billing"],
}
EXTENSIONS = [".exe",".scr",".js",".iso",".html",".htm",".zip",".rar"]

def urls(text): return re.findall(r'https?://[^\s<>"\']+', text, re.I)
def emails(text): return re.findall(r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}', text)

def analyze(text):
    low=text.lower(); matches=[]
    for cat, words in RULES.items():
        found=[w for w in words if w in low]
        if found: matches.append((cat,found))
    us=urls(text); es=emails(text); at=sorted({e for e in EXTENSIONS if e in low})
    flags=[]
    if us: flags.append("Direct URL/link detected")
    if at: flags.append("Potentially dangerous attachment: "+", ".join(at))
    labels={"urgency":"Urgency/time-pressure language","credential_request":"Credential/login/MFA language","financial_request":"Financial/payment request","secrecy":"Secrecy/confidentiality pressure","threat":"Account/security threat language","social_engineering":"Authority/impersonation language"}
    flags += [labels[c] for c,_ in matches]
    score=(2 if us else 0)+(2 if at else 0)+sum(2 if c in ("credential_request","financial_request") else 1 for c,_ in matches)
    if score>=5: verdict,action="MALICIOUS","Block/avoid the message and escalate to the security team."
    elif score>=2: verdict,action="SUSPICIOUS","Do not interact. Verify independently through a trusted channel."
    else: verdict,action="SAFE CANDIDATE","No strong indicators detected; continue normal verification."
    return verdict,score,action,us,es,matches,flags

def main():
    p=argparse.ArgumentParser(description="Analyze an email/message for phishing indicators.")
    p.add_argument("--text", help="Message text to analyze")
    a=p.parse_args()
    if a.text: text=a.text
    else:
        print("Paste the email/message. Press Enter twice when finished:")
        lines=[]
        while True:
            try: line=input()
            except EOFError: break
            if line=="" and lines and lines[-1]=="": break
            lines.append(line)
        text="\n".join(lines).strip()
    if not text: print("No message supplied."); return
    v,s,action,us,es,kw,flags=analyze(text)
    print("\n"+"="*68); print("PROJECT 3 - PHISHING AWARENESS ANALYZER"); print("="*68)
    print(f"Verdict   : {v}\nRisk score: {s}\nAction    : {action}")
    print("\nSuspicious links:\n  - "+("\n  - ".join(us) if us else "None detected"))
    print("\nEmail addresses:\n  - "+("\n  - ".join(es) if es else "None detected"))
    print("\nSuspicious keywords/categories:")
    if kw:
        for c,m in kw: print(f"  - {c}: {', '.join(m)}")
    else: print("  - None detected")
    print("\nRed flags:")
    for f in flags: print("  - "+f)
    if not flags: print("  - No strong red flags detected")
    print("\nWhy it may be unsafe:")
    if v=="MALICIOUS": print("  Multiple phishing indicators were detected. Do not click, scan, open, reply, or provide credentials/payment information.")
    elif v=="SUSPICIOUS": print("  Indicators require independent verification before interaction.")
    else: print("  No strong phishing indicators were detected by this simple rule set.")
    print("\nRecommended workflow: PAUSE -> VERIFY -> REPORT")
    print("="*68)
if __name__=="__main__": main()
