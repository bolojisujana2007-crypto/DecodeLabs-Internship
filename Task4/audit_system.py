#!/usr/bin/env python3
"""Audited Systems - local, read-only blue-team workstation audit.
No settings are changed. Commands are executed locally and only their outputs are used.
"""
import argparse, datetime as dt, json, os, platform, re, shutil, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'outputs'
OUT.mkdir(exist_ok=True)


def run(cmd, timeout=12, shell=False):
    try:
        p = subprocess.run(cmd, shell=shell, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or '').strip(), (p.stderr or '').strip()
    except Exception as e:
        return 99, '', str(e)


def ps(command):
    return run(['powershell','-NoProfile','-NonInteractive','-Command',command])


def add(findings, check, severity, title, evidence, recommendation, cvss=None):
    findings.append({
        'check': check, 'severity': severity, 'title': title,
        'evidence': evidence[:1200], 'recommendation': recommendation,
        'cvss': cvss
    })


def audit_windows(findings, evidence):
    rc,out,err=ps('Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress')
    evidence['firewall'] = out or err
    if rc==0 and out:
        enabled = re.findall(r'"Enabled"\s*:\s*(true|false)', out, re.I)
        if enabled and not all(x.lower()=='true' for x in enabled):
            add(findings,'Step 4 - Network and Endpoint Hygiene','High','Windows firewall is not enabled for every profile',out,'Enable the Windows Defender Firewall for all active profiles and verify inbound rules.',7.5)
        elif enabled:
            evidence['firewall_status']='Enabled on all reported profiles'
    else:
        add(findings,'Step 4 - Network and Endpoint Hygiene','Medium','Firewall state could not be verified automatically',err or 'PowerShell firewall query unavailable','Run Get-NetFirewallProfile in an elevated PowerShell window and verify Enabled=True.',5.3)

    rc,out,err=ps('Get-BitLockerVolume | Select-Object MountPoint,VolumeStatus,ProtectionStatus | ConvertTo-Json -Compress')
    evidence['encryption']=out or err
    if rc==0 and out:
        prot=re.findall(r'"ProtectionStatus"\s*:\s*"?([^,}\"]+)',out,re.I)
        if prot and any('off' in x.lower() or '0'==x.strip() for x in prot):
            add(findings,'Step 4 - Network and Endpoint Hygiene','High','BitLocker protection is off on a reported volume',out,'Enable BitLocker/device encryption and confirm protection is active after backing up recovery information.',7.0)
        elif 'FullyEncrypted' not in out and 'FullyEncrypted' not in out.replace(' ',''):
            add(findings,'Step 4 - Network and Endpoint Hygiene','Medium','Disk encryption state needs manual confirmation',out,'Confirm every sensitive local volume is encrypted and protected by TPM/device security.',5.0)
    else:
        add(findings,'Step 4 - Network and Endpoint Hygiene','Medium','BitLocker state could not be verified automatically',err or 'BitLocker cmdlet unavailable','Open BitLocker settings or run Get-BitLockerVolume as administrator.',5.0)

    rc,out,err=ps('Get-LocalUser Guest | Select-Object Name,Enabled | ConvertTo-Json -Compress')
    evidence['guest_account']=out or err
    if rc==0 and re.search(r'"Enabled"\s*:\s*true',out,re.I):
        add(findings,'Step 3 - Auditing the Human Perimeter','High','Guest account is enabled','Get-LocalUser Guest reports Enabled=True','Disable the Guest account unless there is a documented business requirement.',7.0)

    rc,out,err=ps('Get-LocalGroupMember Administrators | Select-Object Name,PrincipalSource | ConvertTo-Json -Compress')
    evidence['admin_members']=out or err
    if rc==0:
        evidence['admin_members_note']='Review membership manually for least privilege / privilege creep.'

    rc,out,err=ps('Get-WindowsUpdateLog 2>$null | Select-Object -First 1')
    evidence['updates']='Windows Update log generation command available; use Settings/Windows Update to confirm pending patches.'
    # Browser/antivirus checks are intentionally informational because versions vary.


def audit_macos(findings,evidence):
    rc,out,err=run(['/usr/libexec/ApplicationFirewall/socketfilterfw','--getglobalstate'])
    evidence['firewall']=out or err
    if rc==0 and 'enabled' not in out.lower():
        add(findings,'Step 4 - Network and Endpoint Hygiene','High','macOS Application Firewall is not reported as enabled',out,'Enable the Application Firewall and verify Stealth Mode where appropriate.',7.5)
    elif rc!=0:
        add(findings,'Step 4 - Network and Endpoint Hygiene','Medium','macOS firewall state could not be verified automatically',err or out,'Run socketfilterfw --getglobalstate and verify the firewall is enabled.',5.3)

    rc,out,err=run(['fdesetup','status'])
    evidence['encryption']=out or err
    if rc==0 and 'filevault is off' in out.lower():
        add(findings,'Step 4 - Network and Endpoint Hygiene','High','FileVault is off','fdesetup reports FileVault is Off','Enable FileVault and securely retain the recovery method.',7.0)
    elif rc!=0:
        add(findings,'Step 4 - Network and Endpoint Hygiene','Medium','FileVault state could not be verified automatically',err or out,'Run fdesetup status with appropriate permissions.',5.0)

    rc,out,err=run(['dscl','.','-read','/Groups/admin','GroupMembership'])
    evidence['admin_members']=out or err
    evidence['admin_members_note']='Review members for least privilege / privilege creep.'

    rc,out,err=run(['softwareupdate','-l'],timeout=30)
    evidence['updates']=out or err
    if rc==0 and out and 'No new software available' not in out:
        add(findings,'Step 2 - Software Decay & Patch Management','High','Pending macOS software updates detected',out,'Install security-relevant operating system updates promptly and re-run the audit.',7.0)


def audit_linux(findings,evidence):
    if shutil.which('ufw'):
        rc,out,err=run(['ufw','status'])
        evidence['firewall']=out or err
        if rc==0 and re.search(r'Status:\s*inactive',out,re.I):
            add(findings,'Step 4 - Network and Endpoint Hygiene','High','UFW firewall is inactive','ufw status reports inactive','Enable a host firewall appropriate to the distribution and review inbound rules.',7.5)
    elif shutil.which('firewall-cmd'):
        rc,out,err=run(['firewall-cmd','--state'])
        evidence['firewall']=out or err
        if 'running' not in out.lower():
            add(findings,'Step 4 - Network and Endpoint Hygiene','High','firewalld is not running',out,'Enable and configure the host firewall.',7.5)
    else:
        evidence['firewall']='No UFW/firewalld command found; manual verification required.'
        add(findings,'Step 4 - Network and Endpoint Hygiene','Medium','Linux firewall could not be identified automatically',evidence['firewall'],'Verify the active firewall service and inbound policy manually.',5.3)

    if shutil.which('lsblk'):
        rc,out,err=run(['lsblk','-o','NAME,FSTYPE,MOUNTPOINT'])
        evidence['encryption']=out
        if 'crypto_LUKS' not in out:
            add(findings,'Step 4 - Network and Endpoint Hygiene','Medium','Full-disk encryption could not be confirmed','lsblk did not report a crypto_LUKS volume','Confirm the operating system disk is encrypted (for example, LUKS) and document the result.',5.0)

    if shutil.which('getent'):
        rc,out,err=run(['getent','passwd','guest'])
        evidence['guest_account']=out or 'No guest account entry returned.'
        if rc==0 and out:
            add(findings,'Step 3 - Auditing the Human Perimeter','High','Guest account entry exists',out,'Disable/remove an unnecessary guest account and verify least privilege.',7.0)

    if shutil.which('getent'):
        rc,out,err=run(['getent','group','sudo'])
        evidence['admin_members']=out or err
        evidence['admin_members_note']='Review sudo-group membership for least privilege / privilege creep.'

    if shutil.which('apt'):
        rc,out,err=run(['apt','list','--upgradable'],timeout=30)
        evidence['updates']=out or err
        lines=[x for x in out.splitlines() if '/' in x and not x.lower().startswith('listing')]
        if lines:
            add(findings,'Step 2 - Software Decay & Patch Management','High','Upgradable Linux packages detected','\n'.join(lines[:25]),'Install security updates through the distribution package manager and re-run the audit.',7.0)


def generic_checks(findings,evidence):
    # Physical/behavioral hygiene cannot be established reliably from software alone.
    evidence['physical_behavioral']='Manual check required: screen-lock timeout, local credential storage, unencrypted files, removable/rogue USB devices, and verification through secondary trusted channels for suspicious requests.'
    evidence['mfa']='Manual check required: prefer phishing-resistant authenticators (FIDO2/WebAuthn/passkeys) for important accounts.'


def main():
    ap=argparse.ArgumentParser(description='Read-only blue-team workstation audit aligned to the Audited Systems checklist.')
    ap.add_argument('--output',default=str(OUT/'audit_results.json'))
    args=ap.parse_args()
    findings=[]; evidence={}
    os_name=platform.system()
    meta={'timestamp':dt.datetime.now().astimezone().isoformat(),'hostname':platform.node() or 'unknown','os':platform.platform(),'system':os_name,'python':platform.python_version()}
    evidence['identity']=meta
    if os_name=='Windows': audit_windows(findings,evidence)
    elif os_name=='Darwin': audit_macos(findings,evidence)
    elif os_name=='Linux': audit_linux(findings,evidence)
    else:
        add(findings,'Step 1 - Identity Front Door','Medium','Unsupported operating system for automated checks',os_name,'Use the checklist manually and capture terminal evidence.',5.0)
    generic_checks(findings,evidence)
    # Ensure report has at least three auditable observations, without fabricating vulnerabilities.
    if len(findings)<3:
        add(findings,'Step 1 - Identity Front Door','Review','Manual verification required for identity controls','Automated audit did not establish a vulnerability for this control.','Verify passphrase policy and phishing-resistant MFA, then record evidence.',None)
    result={'project':'Project 4: Audited Systems - A Framework for Blue Team Defense','checklist_steps':4,'meta':meta,'findings':findings,'evidence':evidence,'limitations':['This tool is read-only and does not remediate settings.','Physical/behavioral controls, MFA, browser/AV freshness and organizational context require manual verification.','CVSS values in this kit are triage examples for local findings, not official CVSS Calculator scores.']}
    Path(args.output).write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(result,indent=2))
    print(f'\nSaved: {args.output}')

if __name__=='__main__': main()
