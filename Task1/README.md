# Cyber Security Project 1 — Password Strength Checker

## Organization
DecodeLabs — Cyber Security Industrial Training Kit, Batch 2026

## Project Goal
Create a program that checks whether a password is **weak, medium, or strong**.

The implementation follows the requirements in the supplied Project 1 PDF:
- Check password length
- Check use of numbers
- Check use of symbols
- Check use of uppercase letters
- Display the password strength result

## Key Skills Demonstrated
- String handling
- Conditional checks
- Basic security logic
- Input validation
- Character classification

## Files
```text
Cyber_Security_Project_1/
├── password_strength_checker.py
└── README.md
```

## Requirements
- Python 3.9 or newer
- No external Python packages are required.

## How to Run

### Windows
Open Command Prompt or PowerShell in this folder and run:

```bash
python password_strength_checker.py
```

If `python` is not recognized, try:

```bash
py password_strength_checker.py
```

### Linux/macOS
```bash
python3 password_strength_checker.py
```

The program uses a hidden password input where supported, so the password is not displayed while typing.

## Strength Logic

The checker evaluates four criteria:

1. Length is at least 8 characters
2. Contains an uppercase letter
3. Contains a number
4. Contains a symbol

Classification:
- **Weak:** fewer than 8 characters or only 0–1 criteria are satisfied
- **Medium:** 2–3 criteria are satisfied
- **Strong:** all 4 criteria are satisfied

## Example Results

### Weak
A password such as:
```text
hello
```
fails the minimum length and character-variety checks.

### Medium
A password such as:
```text
Hello123
```
contains sufficient length, an uppercase letter, and a number, but no symbol.

### Strong
A password such as:
```text
Hello123!
```
satisfies all four required checks.

> For real-world use, do not use these example passwords. Use a unique password or passphrase.

## Security Notes
- The program does not save passwords to a file.
- Password input is handled locally.
- This is an educational password-strength checker, not a complete password-security system.
- The PDF suggests possible extensions such as checking against common or leaked passwords; that functionality is not required for the core Project 1 criteria and is therefore not included in the base implementation.

## Requirement Verification

| PDF Requirement | Implemented |
|---|---|
| Check password length | Yes |
| Check numbers | Yes |
| Check symbols | Yes |
| Check uppercase letters | Yes |
| Display strength result | Yes |
| String handling | Yes |
| Conditional checks | Yes |
| Security basics | Yes |

## Submission
Submit the ZIP file containing:
- `password_strength_checker.py`
- `README.md`
