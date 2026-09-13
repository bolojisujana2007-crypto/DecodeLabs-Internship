"""
DecodeLabs - Cyber Security Project 2
Basic Encryption & Decryption using an ASCII Caesar-style shift.
Blueprint: IPO Model
I = Input:  Plain text + user-selected shift key
P = Process: ASCII conversion -> shift -> printable ASCII wrap-around
O = Output: Encrypted text + decrypted text
This implementation uses printable ASCII characters (32 to 126).
Spaces and punctuation are supported. Wrap-around keeps the result
inside the printable ASCII range.
"""
ASCII_START = 32
ASCII_END = 126
ASCII_RANGE = ASCII_END - ASCII_START + 1  # 95 printable ASCII chars


def shift_ascii(text: str, shift: int) -> str:
    """Shift printable ASCII characters and wrap around the range."""
    result = []

    for char in text:
        code = ord(char)

        # Keep characters such as newline unchanged.
        if ASCII_START <= code <= ASCII_END:
            shifted_code = ASCII_START + (
                (code - ASCII_START + shift) % ASCII_RANGE
            )
            result.append(chr(shifted_code))
        else:
            result.append(char)

    return "".join(result)


def encrypt(text: str, shift: int) -> str:
    return shift_ascii(text, shift)


def decrypt(ciphertext: str, shift: int) -> str:
    return shift_ascii(ciphertext, -shift)


def main():
    print("=" * 60)
    print("        DecodeLabs - Basic Encryption & Decryption")
    print("=" * 60)

    # INPUT
    plain_text = input("Enter text to encrypt: ")

    while True:
        try:
            shift_key = int(input("Enter shift key (e.g., 3): "))
            break
        except ValueError:
            print("Please enter a valid whole number.")

    # PROCESS
    encrypted_text = encrypt(plain_text, shift_key)
    decrypted_text = decrypt(encrypted_text, shift_key)

    # OUTPUT
    print("\n" + "-" * 60)
    print("OUTPUT")
    print("-" * 60)
    print("Original Text  :", plain_text)
    print("Shift Key      :", shift_key)
    print("Encrypted Text :", encrypted_text)
    print("Decrypted Text :", decrypted_text)
    print("-" * 60)

    if decrypted_text == plain_text:
        print("Status         : SUCCESS - Decryption matched the input.")
    else:
        print("Status         : ERROR - Decryption did not match the input.")


if __name__ == "__main__":
    main()
