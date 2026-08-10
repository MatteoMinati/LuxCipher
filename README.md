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
- `docs/ROADMAP.md` tracks the incremental build plan.
- `docs/SECURITY.md` collects security rules and decisions.
- `docs/IMPLEMENTATION_NOTES.md` explains implementation decisions locally and
  is intentionally ignored by Git.
- `tools/build_implementation_notes_pdf.py` regenerates the implementation
  notes PDF locally under `output/pdf/`.

## Run The Desktop App

LuxCipher currently starts with a secure password generator desktop app.
On first launch it creates a local account; later launches require the master
password before showing the generator.

Requirements:

- Python 3.11 or newer.

Run:

```bash
python -m luxcipher
```

Run tests:

```bash
python -m unittest discover -s tests
```

Regenerate implementation notes PDF:

```bash
python tools/build_implementation_notes_pdf.py
```

## Development Note

Do not commit real vault files, test secrets, recovery phrases, or personal
password data. This repository is for source code and documentation only.
