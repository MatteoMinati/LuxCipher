# Packaging And Distribution

LuxCipher is distributed as a Windows installer attached to a GitHub Release.
This document records how that works and the constraints behind it.

## Status

The release pipeline in `.github/workflows/release.yml` has not completed a run
yet. It is written against the documented behaviour of its tools, but the
`flet build windows` step in particular may need adjustment on the first real
run. Use the manual trigger, described below, rather than burning version tags
while working that out.

## Releasing a version

1. Update `__version__` in `luxcipher/__init__.py`.
2. Commit that on `develop`, merge to `main`.
3. Tag the commit `vX.Y.Z`, matching `__version__` exactly, and push the tag.

The workflow refuses to build if the tag and `__version__` disagree, which is
the usual way a release ends up mislabelled.

The published release is a draft, so nothing becomes public until it is
reviewed and released by hand.

To exercise the build without tagging, run the `release` workflow manually from
the Actions tab. It builds and uploads the artifacts but publishes nothing.

## Why flet build rather than PyInstaller

`flet_desktop` contains no runtime of its own. It downloads the Flet desktop
client on first run. A PyInstaller bundle would therefore still reach the
network the first time a user starts the installed application, which defeats
the point of an offline installer and is a poor property for a security tool.

`flet build windows` compiles a genuine Flutter application instead, so the
client is part of the build rather than a first-run download. The cost is a
heavier toolchain: it needs the Flutter SDK and Visual Studio Build Tools,
which is why the runner image is `windows-latest` rather than anything smaller.

The workflow does not install Flutter itself. Each Flet release requires one
specific Flutter major.minor version, and `flet build` refuses any other: with
a mismatched SDK on PATH it stops to ask whether to install the right one,
which fails in CI because nobody can answer. Passing `--yes` lets Flet install
exactly the version it needs, so the Flutter version follows the Flet pin in
`requirements.txt` instead of being a second number to keep in sync by hand.

## Native dependencies

Two dependencies ship compiled binaries tied to the exact CPython version used
to build:

- `sqlcipher3/_sqlite3.cp313-win_amd64.pyd`
- `_argon2_cffi_bindings/_ffi.pyd`

If the packaged application starts but fails the moment it opens or creates a
vault, a missing one of these is the first thing to check. This is also why the
release workflow pins a single Python version rather than using a matrix.

## Installer decisions

The Inno Setup script is `packaging/luxcipher.iss`. Three choices in it are
deliberate:

- The install is per-user, into `%LOCALAPPDATA%\Programs\LuxCipher`, and asks
  for no administrator rights. Program Files would require elevation and
  separate the program from the per-user data it works with.
- The `AppId` GUID must stay stable forever. It is how Windows tells an upgrade
  from a second parallel installation.
- The uninstaller does not touch `%LOCALAPPDATA%\LuxCipher`.

That last point is the one to defend. The directory holds `vault.db` and
`vault.salt`, which together are the user's entire password collection. There
is no cloud copy, no export, and no reset: if they are deleted the passwords
are gone permanently. An uninstaller that removes them would destroy data the
user cannot reconstruct, so it must not, not even behind a checkbox. The
uninstaller instead tells the user where the vault still is and that removing
it is a manual, irreversible act.

## Code signing

The executable is not signed, so Windows SmartScreen warns on download and
first run. For a password manager this is a trust problem rather than a
cosmetic one: the warning appears exactly where a user should be most careful.

The two ways out:

- Buy an OV or EV code signing certificate and sign in CI. EV certificates
  clear SmartScreen immediately; OV certificates build reputation over time.
- Until then, publish the SHA-256 checksums the workflow generates, and keep
  the build running in public CI from a tagged commit, so anyone can see which
  source produced which binary.

The release notes tell users how to check the hash before running the
installer.
