#!/usr/bin/env python3
"""
nordpass2op - migrate a NordPass export into 1Password.

1Password has no NordPass importer, and NordPass CSV exports are rejected by
1Password's generic CSV importer (folder-only rows, CRLF line endings, mixed
item types in one file). This fixes that, and cleans up after itself.

Two ways in:

  direct    Create items straight in your vault via the `op` CLI. Secrets go
            through JSON templates on a private file descriptor, never through
            argv or your shell history. No browser involved.

  csv       Emit per-type CSVs for 1Password's web importer. No `op` needed.

Stdlib only. No pip install, no network access, no telemetry.

  nordpass2op convert  export.csv           # -> CSVs for the web importer
  nordpass2op direct   export.csv -v Vault  # -> straight into 1Password
  nordpass2op sweep                         # find stray plaintext copies
  nordpass2op clean    <dir>                # shred artifacts + swap files

Full docs: https://github.com/kbelkhir/nordpass-to-1password
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter

__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# NordPass export shape
# ---------------------------------------------------------------------------
# Header as of 2026:
#   name,url,additional_urls,username,password,note,cardholdername,cardnumber,
#   cvc,pin,expirydate,zipcode,folder,shared_folder,full_name,phone_number,
#   email,address1,address2,city,country,state,type,custom_fields
#
# Notes and custom_fields may contain commas AND newlines, so everything here
# goes through the csv module. Do not reach for sed or awk.

TYPE_MAP = {
    "password": "login", "login": "login",
    "note": "note", "secure_note": "note", "securenote": "note",
    "credit_card": "card", "creditcard": "card", "card": "card",
    "payment": "card", "payment_card": "card",
    "identity": "identity", "personal_info": "identity",
    "contact": "identity", "contact_info": "identity",
    "folder": "folder",
    "passkey": "passkey",
}

PAYLOAD_FIELDS = (
    "url", "username", "password", "note", "cardnumber", "cvc", "pin",
    "cardholdername", "expirydate", "full_name", "phone_number", "email",
    "address1", "address2", "city", "country", "state", "custom_fields",
    "additional_urls",
)

LOGIN_COLS = ["title", "website", "username", "password", "notes"]
CARD_COLS = ["title", "card number", "expiry date", "cardholder name",
             "PIN", "bank name", "CVV", "notes"]
NOTE_COLS = ["title", "notes"]

TOTP_RE = re.compile(r"otpauth://|(?:^|[^a-z])(?:totp|otp|2fa|authenticator)(?:[^a-z]|$)", re.I)
B32_RE = re.compile(r"\b[A-Z2-7]{16,}=*\b")

C = {"r": "\033[31m", "g": "\033[32m", "y": "\033[33m", "b": "\033[1m", "0": "\033[0m"}
if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    C = dict.fromkeys(C, "")


def say(msg=""):
    print(msg, flush=True)


def warn(msg):
    say(f"{C['y']}!{C['0']} {msg}")


def die(msg):
    say(f"{C['r']}error:{C['0']} {msg}")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Parsing and classification
# ---------------------------------------------------------------------------

def read_export(path):
    """Read a NordPass CSV. utf-8-sig strips the BOM; newline='' lets the csv
    module handle CRLF and embedded newlines itself."""
    try:
        with open(path, newline="", encoding="utf-8-sig") as fh:
            rows = list(csv.DictReader(fh))
    except FileNotFoundError:
        die(f"no such file: {path}")
    except UnicodeDecodeError:
        die(f"{path} is not UTF-8. Is it really a NordPass export?")
    if not rows:
        die(f"{path} has no data rows")
    if "name" not in rows[0] or "type" not in rows[0]:
        die(f"{path} does not look like a NordPass export "
            f"(missing 'name'/'type' columns). Columns: {', '.join(list(rows[0])[:6])}...")
    return rows


def is_folder_row(row):
    """NordPass emits bare folder rows carrying no credential payload."""
    return not any((row.get(k) or "").strip() for k in PAYLOAD_FIELDS)


def classify(row):
    t = (row.get("type") or "").strip().lower().replace(" ", "_")
    if t in TYPE_MAP:
        return TYPE_MAP[t]
    if (row.get("cardnumber") or "").strip():
        return "card"
    if any((row.get(k) or "").strip()
           for k in ("password", "username", "url", "additional_urls")):
        return "login"
    if any((row.get(k) or "").strip()
           for k in ("full_name", "address1", "phone_number", "city", "country")):
        return "identity"
    if (row.get("note") or "").strip():
        return "note"
    return "unknown"


def norm_expiry(s):
    """Coerce a NordPass expiry into MM/YYYY. Returns (value, parsed_ok)."""
    s = (s or "").strip()
    if not s:
        return "", True
    m = re.match(r"^(\d{1,2})\s*[/\-. ]\s*(\d{2,4})$", s)
    if m:
        mo, yr = int(m.group(1)), m.group(2)
        if len(yr) == 2:
            yr = "20" + yr
        if 1 <= mo <= 12:
            return f"{mo:02d}/{yr}", True
    m = re.match(r"^(\d{4})\s*[/\-. ]\s*(\d{1,2})$", s)
    if m:
        yr, mo = m.group(1), int(m.group(2))
        if 1 <= mo <= 12:
            return f"{mo:02d}/{yr}", True
    return s, False


def parse_custom(raw):
    """custom_fields is usually JSON; fall back to raw text. -> [(label, value)]"""
    raw = (raw or "").strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return [("custom", raw)]
    if isinstance(data, dict):
        data = [{"label": k, "value": v} for k, v in data.items()]
    out = []
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                label = (item.get("label") or item.get("name")
                         or item.get("key") or "field")
                out.append((str(label), str(item.get("value")
                                            or item.get("val") or "")))
            else:
                out.append(("custom", str(item)))
        return out
    return [("custom", raw)]


def extra_note_lines(row, extra=()):
    """Everything 1Password's CSV shape can't hold, folded into notes."""
    parts = []
    if row.get("note"):
        parts.append(row["note"].strip())
    for label, key in extra:
        v = (row.get(key) or "").strip()
        if v:
            parts.append(f"{label}: {v}")
    for label, key in (("NordPass folder", "folder"),
                       ("NordPass shared folder", "shared_folder")):
        v = (row.get(key) or "").strip()
        if v:
            parts.append(f"{label}: {v}")
    cf = parse_custom(row.get("custom_fields"))
    if cf:
        parts.append("--- custom fields ---\n"
                     + "\n".join(f"{k}: {v}" for k, v in cf))
    return "\n\n".join(p for p in parts if p)


def find_totp(row):
    """Return an otpauth:// URI or bare base32 seed if one is hiding in the row."""
    for key in ("custom_fields", "note"):
        blob = (row.get(key) or "")
        if not blob:
            continue
        m = re.search(r"otpauth://\S+", blob)
        if m:
            return m.group(0)
        if TOTP_RE.search(blob):
            m = B32_RE.search(blob)
            if m:
                return m.group(0)
    return None


def analyse(rows):
    """Bucket rows by 1Password item type and collect everything worth warning about."""
    buckets = {"login": [], "card": [], "note": [], "identity": []}
    report = {
        "raw_types": Counter(), "folders": 0, "passkeys": [],
        "totp": [], "bad_expiry": [], "unknown": [], "untitled": 0,
        "total": len(rows),
    }
    for i, row in enumerate(rows, start=2):  # start=2 matches spreadsheet rows
        report["raw_types"][(row.get("type") or "<blank>").strip() or "<blank>"] += 1
        if is_folder_row(row):
            report["folders"] += 1
            continue
        kind = classify(row)
        if kind == "folder":
            report["folders"] += 1
            continue

        title = (row.get("name") or "").strip()
        if not title:
            title = "(untitled)"
            report["untitled"] += 1

        if kind == "passkey":
            report["passkeys"].append(title)
            continue
        if find_totp(row):
            report["totp"].append(title)
        if kind == "card":
            _, ok = norm_expiry(row.get("expirydate"))
            if not ok:
                report["bad_expiry"].append((i, title, row.get("expirydate")))
        if kind == "unknown":
            report["unknown"].append((i, title))
            continue
        buckets[kind].append((title, row))
    return buckets, report


def print_report(report, show_names=True):
    say(f"\n{C['b']}source{C['0']}: {report['total']} rows")
    for t, n in report["raw_types"].most_common():
        say(f"    {t:<18} {n}")
    if report["folders"]:
        say(f"  dropped {report['folders']} folder/empty row(s)")
    if report["untitled"]:
        warn(f"{report['untitled']} item(s) had no name -> titled '(untitled)'; rename after import")

    if report["totp"]:
        warn(f"{len(report['totp'])} item(s) appear to carry a 2FA seed:")
        if show_names:
            for t in report["totp"][:10]:
                say(f"    {t}")
    else:
        warn("no 2FA seeds found anywhere in this export.")
        say("  NordPass does not export TOTP secrets. Re-enrol 2FA per site")
        say("  AFTER verifying the import and BEFORE cancelling NordPass.")

    if report["passkeys"]:
        warn(f"{len(report['passkeys'])} passkey(s) cannot migrate "
             f"(NordPass exports none). Re-register these at each site:")
        if show_names:
            for t in report["passkeys"][:10]:
                say(f"    {t}")
    if report["bad_expiry"]:
        warn(f"{len(report['bad_expiry'])} card expiry date(s) not in MM/YYYY:")
        for i, t, v in report["bad_expiry"]:
            say(f"    row {i}: {t if show_names else '<item>'} -> {v!r}")
    if report["unknown"]:
        warn(f"{len(report['unknown'])} unclassified row(s), NOT written:")
        for i, t in report["unknown"][:10]:
            say(f"    row {i}: {t if show_names else '<item>'}")


# ---------------------------------------------------------------------------
# CSV output
# ---------------------------------------------------------------------------

def write_csvs(buckets, outdir):
    os.makedirs(outdir, exist_ok=True)
    written = []
    plans = (
        ("op-logins.csv", LOGIN_COLS, "login", lambda t, r: [
            t, (r.get("url") or "").strip(), (r.get("username") or "").strip(),
            r.get("password") or "",
            extra_note_lines(r, (("Additional URLs", "additional_urls"),))]),
        ("op-cards.csv", CARD_COLS, "card", lambda t, r: [
            t, (r.get("cardnumber") or "").strip(),
            norm_expiry(r.get("expirydate"))[0],
            (r.get("cardholdername") or "").strip(), (r.get("pin") or "").strip(),
            "", (r.get("cvc") or "").strip(),
            extra_note_lines(r, (("ZIP", "zipcode"),))]),
        ("op-notes.csv", NOTE_COLS, "note", lambda t, r: [t, extra_note_lines(r)]),
        ("op-identities.csv", NOTE_COLS, "identity", lambda t, r: [t, extra_note_lines(r, (
            ("Full name", "full_name"), ("Email", "email"), ("Phone", "phone_number"),
            ("Address 1", "address1"), ("Address 2", "address2"), ("City", "city"),
            ("State", "state"), ("ZIP", "zipcode"), ("Country", "country")))]),
    )
    for fname, cols, key, build in plans:
        if not buckets[key]:
            continue
        path = os.path.join(outdir, fname)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh, lineterminator="\n")
            w.writerow(cols)
            for title, row in buckets[key]:
                w.writerow(build(title, row))
        written.append((path, len(buckets[key])))
    return written


def validate(buckets, outdir):
    """Re-read what we wrote and prove nothing was lost or mangled."""
    path = os.path.join(outdir, "op-logins.csv")
    if not os.path.exists(path):
        return True
    with open(path, newline="", encoding="utf-8") as fh:
        out = list(csv.DictReader(fh))
    src = buckets["login"]
    checks, ok = [], True

    def check(label, cond, detail=""):
        nonlocal ok
        ok &= bool(cond)
        checks.append((label, bool(cond), detail))

    check("login count matches", len(src) == len(out), f"{len(src)} -> {len(out)}")
    for sfield, ofield in (("password", "password"), ("username", "username"),
                           ("url", "website")):
        a = sorted((r.get(sfield) or "") if sfield == "password"
                   else (r.get(sfield) or "").strip() for _, r in src)
        b = sorted((r.get(ofield) or "") if ofield == "password"
                   else (r.get(ofield) or "").strip() for r in out)
        check(f"{sfield} preserved exactly", a == b, f"{sum(1 for x in a if x)} non-empty")
    check("titles aligned", all(t == o["title"] for (t, _), o in zip(src, out)))
    check("every row has 5 fields", all(len(r) == 5 and None not in r.values() for r in out))

    say(f"\n{C['b']}validation{C['0']}")
    for label, passed, detail in checks:
        mark = f"{C['g']}PASS{C['0']}" if passed else f"{C['r']}FAIL{C['0']}"
        say(f"  [{mark}] {label}" + (f"  ({detail})" if detail else ""))
    return ok


# ---------------------------------------------------------------------------
# Direct import through the op CLI
# ---------------------------------------------------------------------------

def op_available():
    if not shutil.which("op"):
        return False, "the `op` CLI is not installed"
    r = subprocess.run(["op", "account", "list"], capture_output=True, text=True)
    if r.returncode != 0 or not r.stdout.strip():
        return False, ("`op` is installed but not signed in. Enable "
                       "Settings > Developer > Integrate with 1Password CLI "
                       "in the desktop app, or run `op account add`.")
    return True, ""


def build_template(kind, title, row):
    """Build a 1Password item JSON template. Values never touch argv."""
    fields, urls = [], []
    notes = extra_note_lines(row) if kind in ("note", "identity") else None

    if kind == "login":
        if (row.get("url") or "").strip():
            urls.append({"href": row["url"].strip(), "primary": True})
        for extra in (row.get("additional_urls") or "").split(","):
            if extra.strip():
                urls.append({"href": extra.strip()})
        fields = [
            {"id": "username", "type": "STRING", "purpose": "USERNAME",
             "value": (row.get("username") or "").strip()},
            {"id": "password", "type": "CONCEALED", "purpose": "PASSWORD",
             "value": row.get("password") or ""},
        ]
        totp = find_totp(row)
        if totp:
            fields.append({"id": "totp", "type": "OTP",
                           "label": "one-time password", "value": totp})
        for label, value in parse_custom(row.get("custom_fields")):
            fields.append({"id": re.sub(r"\W+", "_", label).lower() or "custom",
                           "type": "STRING", "label": label, "value": value,
                           "section": {"id": "nordpass", "label": "NordPass"}})
        notes = (row.get("note") or "").strip()
        category = "LOGIN"

    elif kind == "card":
        exp, _ = norm_expiry(row.get("expirydate"))
        mm_yyyy = ""
        if "/" in exp:
            mo, yr = exp.split("/", 1)
            mm_yyyy = f"{yr}{mo}"          # 1Password MONTH_YEAR wants YYYYMM
        fields = [
            {"id": "ccnum", "type": "CREDIT_CARD_NUMBER", "label": "number",
             "value": (row.get("cardnumber") or "").strip()},
            {"id": "cvv", "type": "CONCEALED", "label": "verification number",
             "value": (row.get("cvc") or "").strip()},
            {"id": "cardholder", "type": "STRING", "label": "cardholder name",
             "value": (row.get("cardholdername") or "").strip()},
            {"id": "pin", "type": "CONCEALED", "label": "PIN",
             "value": (row.get("pin") or "").strip()},
        ]
        if mm_yyyy:
            fields.append({"id": "expiry", "type": "MONTH_YEAR",
                           "label": "expiry date", "value": mm_yyyy})
        notes = extra_note_lines(row, (("ZIP", "zipcode"),))
        category = "CREDIT_CARD"

    elif kind == "identity":
        for fid, label, key in (("firstname", "first name", "full_name"),
                                ("email", "email", "email"),
                                ("defphone", "phone", "phone_number"),
                                ("address1", "address", "address1"),
                                ("city", "city", "city"),
                                ("state", "state", "state"),
                                ("zip", "zip code", "zipcode"),
                                ("country", "country", "country")):
            v = (row.get(key) or "").strip()
            if v:
                fields.append({"id": fid, "type": "STRING", "label": label, "value": v})
        category = "IDENTITY"
    else:
        category = "SECURE_NOTE"

    fields = [f for f in fields if f.get("value")]
    if notes:
        fields.append({"id": "notesPlain", "type": "STRING",
                       "purpose": "NOTES", "value": notes})
    tmpl = {"title": title, "category": category, "fields": fields}
    if urls:
        tmpl["urls"] = urls
    if (row.get("folder") or "").strip():
        tmpl["tags"] = [row["folder"].strip()]
    return tmpl


def op_create(tmpl, vault, dry_run=False):
    """Create one item. The template goes to a 0600 file in a private temp dir,
    so no secret ever appears in argv, the process list, or shell history."""
    if dry_run:
        return True, "dry-run"
    tmpdir = tempfile.mkdtemp(prefix="n2op-", dir=secure_tmp_base())
    path = os.path.join(tmpdir, "item.json")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(tmpl, fh)
        cmd = ["op", "item", "create", "--template", path, "--vault", vault]
        r = subprocess.run(cmd, capture_output=True, text=True)
        return r.returncode == 0, (r.stderr or r.stdout).strip().splitlines()[-1:] and \
            (r.stderr or r.stdout).strip().splitlines()[-1] or ""
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def direct_import(buckets, vault, dry_run=False):
    total = sum(len(v) for v in buckets.values())
    say(f"\n{C['b']}creating {total} item(s) in vault {vault!r}"
        f"{' (dry run)' if dry_run else ''}{C['0']}")
    done = failed = 0
    failures = []
    for kind in ("login", "card", "identity", "note"):
        for title, row in buckets[kind]:
            ok, err = op_create(build_template(kind, title, row), vault, dry_run)
            if ok:
                done += 1
            else:
                failed += 1
                failures.append((title, err))
            n = done + failed
            if n % 10 == 0 or n == total:
                pct = int(n / total * 100)
                sys.stdout.write(f"\r  {n}/{total} ({pct}%)  ok={done} failed={failed}")
                sys.stdout.flush()
    say("")
    if failures:
        warn(f"{len(failures)} item(s) failed:")
        for t, e in failures[:10]:
            say(f"    {t}: {e}")
    return failed == 0


# ---------------------------------------------------------------------------
# Workspace, sweep, clean
# ---------------------------------------------------------------------------

def secure_tmp_base():
    """RAM-backed scratch space where available, so plaintext never hits disk."""
    cands = []
    if hasattr(os, "getuid"):          # POSIX only; Windows has neither
        cands = ["/dev/shm", f"/run/user/{os.getuid()}"]
    for cand in cands:
        if os.path.isdir(cand) and os.access(cand, os.W_OK):
            return cand
    return tempfile.gettempdir()


def make_workspace():
    base = secure_tmp_base()
    path = tempfile.mkdtemp(prefix="nordpass2op-", dir=base)
    os.chmod(path, 0o700)
    ram = base != tempfile.gettempdir()
    if not ram:
        warn("no RAM-backed temp dir on this platform; output goes to disk. "
             "Run `nordpass2op clean` when you are done.")
    return path, ram


SWEEP_NAMES = ("*nordpass*", "op-logins.csv", "op-cards.csv",
               "op-identities.csv", "op-notes.csv")
SWEEP_SIG = "cardholdername,cardnumber,cvc,pin,expirydate"


def sweep(paths=None):
    """Hunt for stray plaintext copies, including the ones people forget:
    editor swap files, clipboard history, trash."""
    import fnmatch
    home = os.path.expanduser("~")
    roots = paths or [home, "/tmp", "/var/tmp", "/dev/shm"]
    skip = {".cache", "node_modules", ".git", "Trash"}
    hits = []
    for root in roots:
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
            dirnames[:] = [d for d in dirnames if d not in skip]
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                low = fn.lower()
                if any(fnmatch.fnmatch(low, p) for p in SWEEP_NAMES):
                    if "/nordpass-to-1password/" in full or full.endswith(".py"):
                        continue
                    hits.append(("name", full))
                    continue
                if low.endswith((".swp", ".swo", ".swn")) and "nordpass" in low:
                    hits.append(("swap", full))
    # Content scan, restricted to plausible sizes to stay quick.
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
            dirnames[:] = [d for d in dirnames if d not in skip]
            for fn in filenames:
                if not fn.lower().endswith((".csv", ".json", ".txt")):
                    continue
                full = os.path.join(dirpath, fn)
                try:
                    if os.path.getsize(full) > 20 * 1024 * 1024:
                        continue
                    with open(full, "r", encoding="utf-8", errors="ignore") as fh:
                        if SWEEP_SIG in fh.read():
                            if not any(h[1] == full for h in hits):
                                hits.append(("content", full))
                except OSError:
                    continue
    return hits


def shred_file(path):
    """Overwrite then unlink. Honest caveat: on a journaling filesystem or SSD
    this is best-effort, not a guarantee."""
    try:
        size = os.path.getsize(path)
        with open(path, "r+b") as fh:
            for _ in range(3):
                fh.seek(0)
                fh.write(os.urandom(size))
                fh.flush()
                os.fsync(fh.fileno())
        os.remove(path)
        return True
    except OSError:
        try:
            os.remove(path)
            return True
        except OSError:
            return False


def clean(target):
    removed = failed = 0
    if os.path.isdir(target):
        for dirpath, _, filenames in os.walk(target):
            for fn in filenames:
                if shred_file(os.path.join(dirpath, fn)):
                    removed += 1
                else:
                    failed += 1
        shutil.rmtree(target, ignore_errors=True)
    elif os.path.exists(target):
        if shred_file(target):
            removed += 1
        else:
            failed += 1
    return removed, failed


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def autodetect():
    home = os.path.expanduser("~")
    cands = []
    for d in ("Downloads", "Desktop", "Documents", ""):
        p = os.path.join(home, d) if d else home
        if not os.path.isdir(p):
            continue
        for fn in os.listdir(p):
            if fn.lower().endswith(".csv") and "nordpass" in fn.lower():
                full = os.path.join(p, fn)
                cands.append((os.path.getmtime(full), full))
    return sorted(cands, reverse=True)[0][1] if cands else None


def resolve_source(arg):
    if arg:
        return arg
    found = autodetect()
    if not found:
        die("no NordPass export given and none found in ~/Downloads. "
            "Pass the path explicitly.")
    say(f"using auto-detected export: {found}")
    return found


def cmd_convert(args):
    src = resolve_source(args.file)
    rows = read_export(src)
    buckets, report = analyse(rows)
    print_report(report, show_names=not args.no_names)

    outdir = args.out
    ram = False
    if not outdir:
        outdir, ram = make_workspace()
    written = write_csvs(buckets, outdir)

    say(f"\n{C['b']}wrote{C['0']}" + ("  (RAM-backed, cleared on reboot)" if ram else ""))
    for path, n in written:
        say(f"  {path}  ({n} items)")
    ok = validate(buckets, outdir)

    say(f"\n{C['b']}next{C['0']}")
    say("  1Password.com > your name > Import data > CSV File")
    say("  Import each file separately, choosing the matching item type.")
    say(f"  When the import is verified:  nordpass2op clean {outdir}")
    return 0 if ok else 1


def cmd_direct(args):
    ok, why = op_available()
    if not ok and not args.dry_run:
        die(why)
    src = resolve_source(args.file)
    rows = read_export(src)
    buckets, report = analyse(rows)
    print_report(report, show_names=not args.no_names)
    total = sum(len(v) for v in buckets.values())
    if not args.yes and not args.dry_run:
        say(f"\nAbout to create {total} item(s) in vault {args.vault!r}.")
        if input("Proceed? [y/N] ").strip().lower() not in ("y", "yes"):
            say("aborted")
            return 1
    good = direct_import(buckets, args.vault, args.dry_run)
    if good and not args.dry_run:
        say(f"\n{C['g']}done{C['0']} - verify in 1Password, then run: "
            f"nordpass2op sweep")
    return 0 if good else 1


def cmd_sweep(args):
    say("scanning for stray plaintext copies...")
    hits = sweep(args.paths or None)
    if not hits:
        say(f"{C['g']}clean{C['0']} - no stray copies found")
        return 0
    say(f"\n{C['y']}found {len(hits)} item(s):{C['0']}")
    for why, path in hits:
        say(f"  [{why:>7}] {path}")
    say("\nEditor swap files and clipboard history are the two people miss.")
    say("Erase with:  nordpass2op clean <path>")
    return 1


def cmd_clean(args):
    for target in args.targets:
        if not os.path.exists(target):
            warn(f"not found: {target}")
            continue
        removed, failed = clean(target)
        say(f"{target}: shredded {removed} file(s)"
            + (f", {failed} failed" if failed else ""))
    say("\nNote: on ext4/btrfs/SSD, overwriting is best-effort. If any migrated")
    say("account is critical, rotate its password rather than trusting the wipe.")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="nordpass2op",
        description="Migrate a NordPass export into 1Password.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="https://github.com/kbelkhir/nordpass-to-1password")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("convert", help="emit CSVs for 1Password's web importer")
    c.add_argument("file", nargs="?", help="NordPass CSV (auto-detected if omitted)")
    c.add_argument("-o", "--out", help="output dir (default: RAM-backed temp dir)")
    c.add_argument("--no-names", action="store_true",
                   help="omit item names from the report")
    c.set_defaults(func=cmd_convert)

    d = sub.add_parser("direct", help="create items directly via the op CLI")
    d.add_argument("file", nargs="?", help="NordPass CSV (auto-detected if omitted)")
    d.add_argument("-v", "--vault", default="Personal", help="target vault")
    d.add_argument("-y", "--yes", action="store_true", help="skip confirmation")
    d.add_argument("-n", "--dry-run", action="store_true",
                   help="build every template but create nothing")
    d.add_argument("--no-names", action="store_true",
                   help="omit item names from the report")
    d.set_defaults(func=cmd_direct)

    s = sub.add_parser("sweep", help="find stray plaintext copies on this machine")
    s.add_argument("paths", nargs="*", help="dirs to scan (default: HOME /tmp /dev/shm)")
    s.set_defaults(func=cmd_sweep)

    k = sub.add_parser("clean", help="shred migration artifacts")
    k.add_argument("targets", nargs="+", help="files or dirs to erase")
    k.set_defaults(func=cmd_clean)

    args = p.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        say("\naborted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
