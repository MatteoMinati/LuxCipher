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
- Store local account metadata on the device only.
- Store a password verifier, never the master password or derived key.
- Compare password verifiers with constant-time comparison.
- Keep vault entry titles, usernames, passwords, URLs, and notes inside the
  encrypted payload once storage is implemented.

## Decisions To Make Before Coding Crypto

- Programming language and runtime: Python desktop app with Tkinter for now.
- KDF choice, such as Argon2id, scrypt, or PBKDF2.
- Authenticated encryption choice, such as XChaCha20-Poly1305 or AES-GCM.
- Vault file format.
- UI direction: desktop app first. Web can be added later.

## Data Model Decision

The current vault model represents decrypted in-memory data only. It is not the
encrypted file format.

The future encrypted file should keep only public cryptographic metadata outside
the ciphertext, such as schema version, KDF name, salt, KDF parameters,
encryption algorithm, and nonce or IV.

## Local Authentication Decision

LuxCipher uses local-only accounts. There is no remote identity provider, no
cloud login, and no server-side account recovery in the current design.

The local account record stores:

- account schema version;
- local account id;
- username;
- creation and update timestamps;
- public scrypt parameters;
- password verifier.

The local account record does not store:

- master password;
- derived master key;
- decrypted vault data;
- vault entry data.

The current verifier is produced by deriving a key with scrypt and then applying
HMAC-SHA256 with a LuxCipher-specific context string. Verification recomputes
the verifier from the candidate master password and compares it with
`hmac.compare_digest`.

Stored KDF parameters are validated with upper bounds before use. This keeps a
tampered local account record from requesting unreasonable scrypt parameters.

Local account metadata is stored as JSON on the user's device. Writes are
performed through a temporary file and atomic replacement, and existing account
metadata is not overwritten unless the caller explicitly asks for that behavior.
File permissions are restricted to the current user where the operating system
supports it.

This protects against accidentally storing the master password. It does not make
a weak master password safe if an attacker obtains the local account record,
because offline guessing is still possible. A strong master password remains
mandatory.

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
