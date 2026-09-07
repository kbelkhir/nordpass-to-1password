# nordpass-to-1password

Migrate a NordPass export into 1Password — without hand-editing CSVs, and without leaving your passwords scattered across your disk afterwards.

```bash
nordpass2op direct                # straight into 1Password via the op CLI
nordpass2op sweep                 # find every stray plaintext copy
```

Python 3.8+, standard library only. No `pip install`, no network calls, no telemetry.

## Why this exists

1Password has dedicated importers for Bitwarden, Dashlane, KeePass, KeePassXC, Keeper, LastPass, Delinea and RoboForm. **NordPass is not among them.**

And a NordPass CSV won't go through 1Password's generic CSV importer as-is, because:

- it contains **folder-only rows** with no credential payload, which the importer rejects
- it uses **CRLF line endings**
- it packs **every item type into one file**, while 1Password imports one type at a time
- `note` and `custom_fields` may contain **commas and embedded newlines**, so naive `sed`/`awk` cleanup silently corrupts them

There's no existing open-source tool for this hop. [`pass-import`](https://github.com/roddhjav/pass-import) reads NordPass but cannot write 1Password. This fills the gap.

## Install

```bash
git clone https://github.com/kbelkhir/nordpass-to-1password
cd nordpass-to-1password
install -m 755 nordpass2op.py ~/.local/bin/nordpass2op
```

Or just run `python3 nordpass2op.py` in place.

## Export from NordPass

Export lives in the **desktop app or Web Vault only** — not mobile.

Settings (cog, top-left) → **Import and Export** → **Export items** → enter your master password → save the `.csv`.

## Usage

### Direct import (recommended)

Creates items straight in your vault through the [`op` CLI](https://developer.1password.com/docs/cli/). No browser, no intermediate files to clean up.

```bash
nordpass2op direct --vault "Personal"
```

Requires `op` installed and signed in (desktop app → Settings → Developer → *Integrate with 1Password CLI*).

Item templates are written to a `0600` file in a private temp directory and passed to `op` by path — **secrets never appear in `argv`, the process list, or your shell history.** 1Password's own docs recommend exactly this over assignment statements.

Preview without writing anything:

```bash
nordpass2op direct --dry-run
```

### CSV import

If you'd rather not use `op`:

```bash
nordpass2op convert
```

Writes per-type CSVs, already in 1Password's canonical column order, to a RAM-backed temp directory. Import each at *1password.com → your name → Import data → CSV File*, one file at a time, choosing the matching item type.

| File | Import as |
|---|---|
| `op-logins.csv` | Login |
| `op-cards.csv` | Credit Card |
| `op-notes.csv` | Secure Note |
| `op-identities.csv` | Secure Note |

### Clean up afterwards

```bash
nordpass2op sweep                 # locate stray copies
nordpass2op clean /path/to/dir    # overwrite and remove them
```

`sweep` looks in the places people forget: **editor swap files** (`.swp` — Neovim keeps one after you open the export, independent of the file itself), **clipboard history**, `/tmp`, `/dev/shm`, and any CSV/JSON carrying the NordPass header signature.

## What migrates, and what doesn't

| | Status |
|---|---|
| Logins — title, URL, username, password, notes | Migrates |
| Additional URLs | Migrates (direct mode: extra URL entries) |
| Credit cards | Migrates, expiry normalised to 1Password's format |
| Secure notes | Migrates |
| Identities | Migrates (direct mode: real Identity item; CSV mode: Secure Note) |
| Custom fields | Direct mode: real fields in a *NordPass* section. CSV mode: appended to notes |
| Folders | Direct mode: item tags. CSV mode: recorded in notes |
| **TOTP / 2FA seeds** | **Usually absent.** NordPass has no TOTP column. If a seed is found in `custom_fields`, direct mode promotes it to a real OTP field — otherwise **you must re-enrol 2FA per site** |
| **Passkeys** | **Cannot migrate.** NordPass exports none. Re-register at each site |

The tool tells you which of these apply to *your* export rather than making you find out later.

> **Re-enrol 2FA and passkeys before cancelling NordPass.** If an enrolment goes wrong on an account you can't otherwise reach, the old vault is your only way back in.

## Security

- **Nothing leaves your machine.** No network calls anywhere in the tool.
- **Scratch space is RAM-backed** (`/dev/shm`, else `/run/user/$UID`) so plaintext never reaches disk when it can be helped.
- **All output is `0600`.**
- On **Windows** neither of those applies — there is no RAM-backed temp dir and POSIX modes are not meaningful, so output lands on disk with default permissions. The tool says so at runtime. Run `clean` promptly.
- **Secrets never touch `argv`.**
- **`.gitignore` blocks `*.csv`** so you can't accidentally commit a vault into this repo.

`clean` overwrites before unlinking, but be honest about the limits: **on a journaling filesystem or an SSD, overwriting in place is best-effort, not a guarantee.** Wear-levelling and the journal may retain the original blocks. If a migrated account is genuinely critical, rotate its password rather than trusting the wipe.

## Correctness

`convert` validates its own output — re-reading what it wrote and checking that passwords, usernames and URLs are preserved **byte-exact**, that titles stay aligned, and that every row has the right field count.

The test suite covers CRLF, BOM, embedded newlines, passwords containing both commas and double quotes, folder rows, unparseable expiry dates, unknown item types, and blank names.

```bash
python3 tests/test_nordpass2op.py     # or: python3 -m pytest tests/ -q
```

Verified against a real 238-item NordPass export: 238 in, 238 out, zero positional mismatches.

## Contributing

NordPass has changed its export format before and will again. If yours has different columns, open an issue with **the header row only** — never a row containing credentials.

## License

MIT
