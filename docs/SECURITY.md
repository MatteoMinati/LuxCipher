# Security Notes

LuxCipher should stay conservative. The goal is to build a password manager
that is understandable without inventing new cryptography.

## Rules

- Never store the master password.
- Never log passwords, keys, plaintext vaults, or decrypted entries.
- Generate passwords with a cryptographically secure random source.
- Never commit real vault files or real secrets.
- Use a well-reviewed cryptographic library.
- Use authenticated encryption, not encryption alone.
- Use a unique random salt for key derivation.
- Use a unique random nonce or IV for each encryption operation.
- Treat all decrypted data as sensitive.

## Decisions To Make Before Coding Crypto

- Programming language and runtime.
- KDF choice, such as Argon2id, scrypt, or PBKDF2.
- Authenticated encryption choice, such as XChaCha20-Poly1305 or AES-GCM.
- Vault file format.
- CLI, desktop app, browser extension, or web app first.

## Early Threat Model

LuxCipher should initially protect against:

- Someone reading the local vault file.
- Someone modifying the local vault file.
- Accidental commits of local secrets.

LuxCipher does not yet protect against:

- Malware running on the unlocked machine.
- A compromised clipboard.
- A weak master password.
- Phishing or fake unlock screens.
