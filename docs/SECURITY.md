# Security Notes

LuxCipher should stay conservative. The goal is to build a password manager
that is understandable without inventing new cryptography.

## Rules

These are constraints on the code, not aspirations. Where the implementation
falls short of one, the gap is recorded under Early Threat Model below.

- Never store the master password or the derived master key.
- Never log passwords, keys, or decrypted entries.
- Generate passwords with a cryptographically secure random source.
- Never commit real vault files or real secrets.
- Use a well-reviewed cryptographic library. Do not invent cryptography.
- Use authenticated encryption, not encryption alone.
- Use a unique random salt for key derivation.
- Use a unique random nonce or IV for each encryption operation.
- Treat all decrypted data as sensitive.
- Keep account data on the device only.
- Keep every credential field inside the encrypted database, including the
  service name and the username.
- Confirm before destroying anything the user cannot get back.
- Never destroy key material to recover from an error. Refuse and report
  instead, so a recoverable vault is never made unrecoverable.

## Decisions Made

- Programming language and runtime: Python desktop app built with Flet.
- KDF: Argon2id, via `argon2-cffi`, with the OWASP parameters (time cost 3,
  64 MiB memory, parallelism 4, 32-byte output).
- Authenticated encryption: delegated to SQLCipher, which encrypts each database
  page with AES-256-CBC and authenticates it with a per-page HMAC.
- Storage format: a SQLCipher database, not a hand-rolled vault file.
- UI direction: desktop app first. Web can be added later.

## Storage Decision

Credentials live in an encrypted SQLCipher database rather than in a custom
encrypted file. This avoids designing a vault format, a nonce scheme and a
tamper-detection scheme by hand, which was the main risk of the earlier plan.

The consequence is that the whole database, including the username in the
`metadata` table, is opaque on disk. Nothing but the salt is stored outside the
ciphertext.

`secure_delete` is enabled so overwritten rows are not left readable in freed
pages, and `temp_store` is set to memory so query spill files never touch the
disk in plaintext.

## Local Authentication Decision

LuxCipher uses local-only accounts. There is no remote identity provider, no
cloud login, and no server-side account recovery.

There is no separate password verifier. The master password is verified by
whether SQLCipher can decrypt page 1 of the database. This keeps a single
secret-dependent path instead of two, but it has a real consequence: a wrong
master password and a database that was never readable with that key are
indistinguishable, and both surface as the same error.

The device stores:

- the encrypted database, at `%LOCALAPPDATA%\LuxCipher\vault.db`;
- a random 16-byte Argon2id salt, at `%LOCALAPPDATA%\LuxCipher\vault.salt`.

It never stores the master password or the derived master key.

Both files are required. The salt is never regenerated when the existing file is
the wrong size, because doing so would derive a different key and leave the
database permanently undecryptable while reporting only a wrong password.

The master password can be changed from inside an unlocked vault. `PRAGMA rekey`
re-encrypts every page under the key derived from the new password. The salt is
deliberately left alone: rotating it as well would invalidate every existing
backup without warning.

Backups copy the database and the salt together into a timestamped folder under
the user's Documents directory. Copying only the database would produce a file
that can never be opened. A backup keeps the key it was written with, so a
backup taken before a password change still needs the older password.

None of this makes a weak master password safe: an attacker holding the database
can guess offline, bounded only by Argon2id. A strong master password remains
mandatory, and account creation enforces a 12 character minimum.

## Auto-Type Decision

Auto-type types a stored username and password into whatever window currently
has focus, triggered by a global hotkey. It exists because the alternative,
copying through the clipboard, is both slower and no safer.

It is the only feature that deliberately sends a secret into a window LuxCipher
does not own, so it is disabled by default and each of these rules refuses to
type rather than guess:

- the vault must be unlocked, and the feature explicitly enabled;
- the focused window must have a title;
- some stored service name must appear in that title, and names shorter than
  three characters are never matched, because they match nearly anything;
- when several services match, the longest and therefore most specific wins;
- when several credentials tie, the most recently updated wins, which is a
  guess but a contained one: they belong to the same service, so the worst case
  is a failed login rather than a password sent to a stranger;
- the focused window is re-checked immediately before typing, because the user
  may have switched windows since pressing the hotkey;
- LuxCipher never types into its own window.

Two risks remain, and cannot be removed by better matching:

- Window titles are chosen by the program that owns them. A hostile
  application can title itself after a service in order to be handed those
  credentials. Every title-based auto-type implementation shares this
  weakness. The defence is that the machine must be trusted, which is already
  a stated assumption of the threat model.
- If the focused control is not a login field, the password is typed wherever
  the caret happens to be, in plain text, and may end up in a chat message, a
  search box, or a document. The Enter that follows may then submit it.

Both are the user's risk to accept, which is why the feature is opt-in and why
the interface and the README describe the failure modes rather than only the
benefit.

## Early Threat Model

LuxCipher should initially protect against:

- Someone reading the local vault file.
- Someone modifying the local vault file.
- Accidental commits of local secrets.

LuxCipher does not yet protect against:

- Malware running on the unlocked machine.
- A compromised clipboard. A copied password is erased 30 seconds after the
  copy, and only if the clipboard still holds it, so anything the user copied in
  the meantime survives. Anything reading the clipboard inside that window still
  sees the password, and clipboard history features may retain it regardless.
- A weak master password, beyond the 12 character minimum.
- Phishing or fake unlock screens.
- A hostile local program naming its window after a stored service in order to
  receive credentials through auto-type. See the auto-type section above.
- Another local user account reading the database file. Permissions are set with
  `chmod(0o600)`, which has no effect on Windows, the only supported platform.
  The file contents stay encrypted regardless.
- Recovering the master key from process memory. Python cannot reliably zero the
  derived key, and it stays resident while the vault is unlocked.
