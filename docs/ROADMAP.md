# LuxCipher Roadmap

This roadmap keeps the project small and teachable. Each step should be
completed, reviewed, and tested before moving to the next one.

## Step 1: Vault Shape — done

- Start with a secure desktop password generator.
- Define the shape of a stored credential.

An early version modelled the decrypted vault in memory in
`luxcipher/vault_model.py` and planned to serialize it to an encrypted file.
Steps 2 and 3 replaced that with SQLCipher, which owns both the storage format
and the encryption, so the in-memory model was removed rather than left
unreachable. It is still in the Git history if the file-format approach is ever
revisited.

A credential is now one row in the `accounts` table:

- `id`
- `service`
- `username`
- `password`

`title`, `url`, `notes` and the `createdAt` / `updatedAt` timestamps from the
original sketch are not implemented yet.

## Step 2: Local Authentication And Key Derivation — done

- Verify the master password without storing it.
- Use a random salt for key derivation.
- Derive the vault encryption key from the master password.

Current status:

- `derive_master_key` derives a 32-byte key with Argon2id using the OWASP
  parameters (time cost 3, 64 MiB, parallelism 4).
- `get_or_create_salt` keeps a random 16-byte salt in `vault.salt`, next to the
  database. It refuses to replace a corrupted salt, because regenerating one
  would make an existing vault permanently undecryptable.
- There is no separate password verifier. The master password is verified by
  whether SQLCipher can decrypt page 1 of the database, so a wrong password is
  indistinguishable from a database that was never readable with that key.
- `normalize_username` and `is_master_password_strong_enough` enforce the
  username format and the 12 character minimum at account creation.
- The desktop UI shows first-run account creation and later login before the
  vault.

## Step 3: Local Encryption — done

- Encrypt the vault before writing it to disk.
- Authenticate ciphertext so tampering is detected.

Current status:

- `AccountStore` opens the database with `PRAGMA key`, so SQLCipher encrypts
  every page with AES-256-CBC and authenticates it with per-page HMAC.
- `secure_delete` and an in-memory temp store are enabled so plaintext is not
  left in freed pages or spill files.
- The username is stored in an encrypted `metadata` table, not in the clear.

## Step 4: Basic Operations — done

- Create a vault, unlock it, add, list, search, read, update and delete an
  entry are all implemented.
- Credentials carry `created_at` and `updated_at` stamps. Vaults written before
  those columns existed are migrated in place on open, keeping empty stamps
  rather than inventing times.
- Deleting asks for confirmation first, because there is no undo and no
  recycle bin.

## Step 5: Key And Vault Management — done

- The master password can be changed. `PRAGMA rekey` re-encrypts every page
  under the new key. The Argon2id salt does not change, so `vault.salt` stays
  valid and still has to be kept.
- The vault can be backed up. `VACUUM INTO` writes a consistent encrypted
  snapshot without closing the vault, and the salt is copied beside it, because
  a database without its salt can never be opened again.
- A backup stays encrypted under the master password in force when it was
  taken. Changing the master password afterwards does not re-key old backups.

## Step 6: Tests

- Test unlock failure with a wrong password. — done
- Test that the database is unreadable on disk. — done
- Test CRUD behaviour without real passwords. — done
- Test schema migration from an older vault. — done
- Test re-keying and backup round-trips. — done
- Test corrupted vault detection.
