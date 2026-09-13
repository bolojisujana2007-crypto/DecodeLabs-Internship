# DecodeLabs Cyber Security - Project 2
## Project
**Basic Encryption & Decryption**
This project follows the requirements in the provided DecodeLabs Project 2 PDF.
### Required functionality
1. Accept user text.
2. Accept a user-selected shift key.
3. Encrypt the text using a basic Caesar-style technique.
4. Decrypt the encrypted text.
5. Display encrypted and decrypted output.
## IPO Blueprint
| Stage | What happens |
|---|---|
| **Input** | User enters plain text and a shift key |
| **Process** | Convert each printable character to ASCII, apply the shift, and wrap around the printable ASCII range |
| **Output** | Show original text, encrypted text, decrypted text, and verification status |

## Logic

For a printable ASCII character:

**Encryption**

`new_code = 32 + ((ASCII_code - 32 + shift) % 95)`

**Decryption**

`original_code = 32 + ((ASCII_code - 32 - shift) % 95)`

The `% 95` operation performs the **wrap-around**. Therefore, a character that moves beyond ASCII 126 continues again from ASCII 32.

Characters outside the printable ASCII range (for example, a newline) are left unchanged.

## Run

```bash
python encryption_decryption.py
```

### Example

Input:
```text
HELLO
```

Shift:
```text
3
```

The program displays:
- Original Text
- Shift Key
- Encrypted Text
- Decrypted Text
- SUCCESS verification

> Note: This is a learning/demo cipher, not a secure modern encryption algorithm.
