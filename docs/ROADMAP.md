# LuxCipher Roadmap

This roadmap keeps the project small and teachable. Each step should be
completed, reviewed, and tested before moving to the next one.

## Step 1: Vault Shape

- Start with a secure desktop password generator.
- Decide what a password entry contains.
- Decide how entries are identified.
- Decide what metadata can stay unencrypted, if anything.

Suggested entry fields:

- `id`
- `title`
- `username`
- `password`
- `url`
- `notes`
- `createdAt`
- `updatedAt`

## Step 2: Key Derivation

- Derive an encryption key from the master password.
- Use a random salt per vault.
- Store the salt, not the master password.
- Pick a proven KDF before writing encryption code.

## Step 3: Local Encryption

- Encrypt the vault before writing it to disk.
- Authenticate ciphertext so tampering is detected.
- Store only the encrypted vault payload and required public parameters.

## Step 4: Basic Operations

- Create a vault.
- Unlock a vault.
- Add an entry.
- List entry titles.
- Read one entry.
- Update an entry.
- Delete an entry.

## Step 5: Tests

- Test round-trip encryption and decryption.
- Test unlock failure with a wrong password.
- Test corrupted vault detection.
- Test CRUD behavior without real passwords.
