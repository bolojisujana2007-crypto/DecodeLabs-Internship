#!/usr/bin/env python3
"""
DecodeLabs Cyber Security - Project 1
Password Strength Checker

Evaluates a password as Weak, Medium, or Strong using:
- Password length
- Uppercase letters
- Numbers
- Symbols
"""

import string
import getpass


def check_password_strength(password: str) -> tuple[str, list[str]]:
    """Return strength and security observations for a password."""
    checks = {
        "length": len(password) >= 8,
        "uppercase": any(ch.isupper() for ch in password),
        "number": any(ch.isdigit() for ch in password),
        "symbol": any(ch in string.punctuation for ch in password),
    }

    score = sum(checks.values())

    if len(password) < 8 or score <= 1:
        strength = "WEAK"
    elif score in (2, 3):
        strength = "MEDIUM"
    else:
        strength = "STRONG"

    feedback = []
    if len(password) < 8:
        feedback.append("Use at least 8 characters.")
    if not checks["uppercase"]:
        feedback.append("Add at least one uppercase letter.")
    if not checks["number"]:
        feedback.append("Add at least one number.")
    if not checks["symbol"]:
        feedback.append("Add at least one symbol.")

    if not feedback:
        feedback.append("Good character variety and length.")

    return strength, feedback


def main() -> None:
    print("=" * 50)
    print("       DecodeLabs Password Strength Checker")
    print("=" * 50)
    print("Enter a password to evaluate it.")
    print("Your password is checked locally and is not stored.\n")

    password = getpass.getpass("Password: ")

    strength, feedback = check_password_strength(password)

    print("\nPassword Strength:", strength)
    print("\nChecks:")
    print(f"  Length (8+ characters): {'PASS' if len(password) >= 8 else 'FAIL'}")
    print(f"  Uppercase letter:      {'PASS' if any(c.isupper() for c in password) else 'FAIL'}")
    print(f"  Number:                {'PASS' if any(c.isdigit() for c in password) else 'FAIL'}")
    print(f"  Symbol:                {'PASS' if any(c in string.punctuation for c in password) else 'FAIL'}")

    print("\nFeedback:")
    for item in feedback:
        print(" -", item)


if __name__ == "__main__":
    main()
