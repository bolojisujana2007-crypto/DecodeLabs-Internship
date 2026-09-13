# Auditor's Toolkit — Execution Matrix

The following commands mirror the training deck's Windows/macOS examples. Run them locally in the appropriate shell and save only non-secret output.

| Security check | Windows PowerShell | macOS Terminal |
|---|---|---|
| Verify firewall | `Get-NetFirewallProfile` | `socketfilterfw --getglobalstate` |
| Check encryption | `Get-BitLockerVolume` | `fdesetup status` |
| Audit admin rights | `Get-LocalGroupMember Administrators` | `dscl . -read /Groups/admin` |
| Find Shadow IT | `Get-ItemProperty` (targeted app inventory) | `ls /Applications` |
| Search for updates | `Get-WUList` where the Windows Update module is available | `softwareupdate -l` |

The Python audit script uses safe, read-only variants of these checks where practical and adds Linux equivalents.

**Do not paste passwords, recovery keys, API keys, tokens, or private personal data into the report.**
