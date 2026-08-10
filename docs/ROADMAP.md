# LuxCipher Roadmap

This roadmap keeps the project small and teachable. Each step should be
completed, reviewed, and tested before moving to the next one.

## Step 1: Vault Shape

- Start with a secure desktop password generator.
- Define the decrypted vault model in `luxcipher/vault_model.py`.
- Keep entry fields inside the future encrypted payload.
- Keep only public crypto parameters outside the future ciphertext.

Suggested entry fields:

- `id`
- `title`
- `username`
- `password`
- `url`
- `notes`
- `createdAt`
- `updatedAt`

Current model status:

- `VaultEntry` stores one decrypted password record in memory.
- `VaultData` stores the decrypted vault payload in memory.
- Persistence and encryption are intentionally not implemented yet.

## Step 2: Local Authentication And Key Derivation

- Create local-only account metadata.
- Verify the master password without storing it.
- Use a random salt per local account.
- Store public KDF parameters and a verifier, not the master password.
- Derive an encryption key from the master password before vault storage.
- Use a random salt per vault if account authentication and vault encryption
  need separate derivation contexts.

Current model status:

- `LocalAccount` stores local account metadata.
- `ScryptParameters` stores public KDF parameters.
- `verify_master_password` checks a candidate password with constant-time
  comparison.
- Vault encryption key derivation is intentionally not implemented yet.

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
