# LuxCipher

Devilishly simple security for your passwords.

LuxCipher is a password manager project built step by step, with security and
clarity as first-class goals.

## Project Goals

- Store passwords only in encrypted form.
- Keep the master password out of storage.
- Prefer proven cryptographic libraries over custom crypto.
- Make the code small enough to understand while it grows.

## Suggested First Milestones

1. Define the vault data model.
2. Add password-based key derivation.
3. Encrypt and decrypt a local vault file.
4. Add commands for creating, listing, reading, updating, and deleting entries.
5. Add tests for the security-critical paths.

## Repository Structure

- `luxcipher/` contains the desktop app and core logic.
  - `auth.py` derives the master key with Argon2id and holds the credential rules.
  - `account_store.py` stores credentials in an encrypted SQLCipher database.
  - `password_generator.py` generates passwords and scores their strength.
  - `desktop_app.py` is the Flet user interface.
- `docs/ROADMAP.md` tracks the incremental build plan.
- `docs/SECURITY.md` collects security rules and decisions.
- `docs/IMPLEMENTATION_NOTES.md` explains implementation decisions locally and
  is intentionally ignored by Git.
- `tools/build_implementation_notes_pdf.py` regenerates the implementation
  notes PDF locally under `output/pdf/`. It reads the untracked notes file, so
  it only works in a checkout that already has a local copy of it.

## Run The Desktop App

LuxCipher currently starts with a secure password generator desktop app.
On first launch it creates a local account; later launches require the master
password before showing the generator.

Requirements:

- Python 3.11 or newer.
- **Windows.** The clipboard and window handling call the Win32 API directly,
  so the app does not currently start on macOS or Linux.

Install and run:

```bash
pip install -r requirements.txt
```

```bash
python -m luxcipher
```

Run tests:

```bash
python -m unittest discover -s tests
```

Where LuxCipher keeps your data:

- `%LOCALAPPDATA%\LuxCipher\vault.db` — the encrypted SQLCipher database.
- `%LOCALAPPDATA%\LuxCipher\vault.salt` — the Argon2id salt.

Both are required to unlock the vault. **Back them up together**: the database
cannot be decrypted without its salt, and there is no recovery path. Set
`LUXCIPHER_HOME` to keep them somewhere else.

Regenerate implementation notes PDF (needs `pip install -r requirements-dev.txt`):

```bash
python tools/build_implementation_notes_pdf.py
```

## Development Note

Do not commit real vault files, test secrets, recovery phrases, or personal
password data. This repository is for source code and documentation only.
