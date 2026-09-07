# LuxCipher

[![tests](https://github.com/MatteoMinati/LuxCipher/actions/workflows/tests.yml/badge.svg)](https://github.com/MatteoMinati/LuxCipher/actions/workflows/tests.yml)

Devilishly simple security for your passwords.

LuxCipher is a password manager project built step by step, with security and
clarity as first-class goals.

## Features

- Store, search, edit and delete credentials in an encrypted vault.
- Generate strong passwords, with a strength meter based on estimated entropy.
- Copy a username or password to the clipboard; it is erased 30 seconds later.
- Change the master password, which re-encrypts the whole vault.
- Back up the vault and its salt together, in one click.
- Automatic lock after 20 minutes of inactivity.

Keyboard: `Esc` locks the vault, `Ctrl+F` jumps to the search box.

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
- `docs/PACKAGING.md` explains how releases and the installer are built.
- `packaging/luxcipher.iss` is the Inno Setup installer script.
- `.github/workflows/` runs the tests on every push and builds the release.
- `docs/IMPLEMENTATION_NOTES.md` explains implementation decisions locally and
  is intentionally ignored by Git.
- `tools/build_implementation_notes_pdf.py` regenerates the implementation
  notes PDF locally under `output/pdf/`. It reads the untracked notes file, so
  it only works in a checkout that already has a local copy of it.

## Install

Download the latest installer from the
[Releases page](../../releases) and run it. It installs per-user into
`%LOCALAPPDATA%\Programs\LuxCipher` and needs no administrator rights.

The installer is not code signed, so Windows SmartScreen will warn you. Before
running it, check the file against the `SHA256SUMS.txt` published with the
release:

```powershell
Get-FileHash .\LuxCipher-<version>-setup.exe -Algorithm SHA256
```

Uninstalling removes the program and leaves your vault in
`%LOCALAPPDATA%\LuxCipher` untouched, so reinstalling finds your passwords
again.

## Run From Source

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
cannot be decrypted without its salt, and there is no recovery path. The backup
button in the app does exactly that, writing both files into a timestamped
folder under `Documents\LuxCipher Backups`. Set `LUXCIPHER_HOME` to keep the
live vault somewhere else.

A backup stays encrypted with the master password that was in force when it was
taken, so changing the master password later does not update older backups.

Regenerate implementation notes PDF (needs `pip install -r requirements-dev.txt`):

```bash
python tools/build_implementation_notes_pdf.py
```

## Development Note

Do not commit real vault files, test secrets, recovery phrases, or personal
password data. This repository is for source code and documentation only.
