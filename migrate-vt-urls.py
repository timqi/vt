#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["pexpect>=4.9"]
# ///
"""Migrate legacy vt://mac/... URLs in given files to the v2 envelope format.

Strategy:
  - Decrypt every URL in a single `vt inject -i` pass (one Touch ID prompt
    for the whole batch). For type=1 (TOTP) URLs we momentarily flip the
    type byte to 0 in the stub fed to vt — the legacy agent path then
    returns the raw base32 seed instead of generating a 6-digit code.
    This trick relies on legacy ciphertexts having no AAD; v2 closes that
    hole, and `vt ssh agent --no-legacy-decrypt` retires this path.
  - Re-encrypt each plaintext via `vt create` (no Touch ID; encrypt@vt is
    unauthenticated by design) and capture the new vt://0... or vt://1...
    URL.
  - Atomically rewrite each input file. Pass `--backup` to leave a
    `<file>.vt-migrate-backup` copy next to each modified file.

Requires `vt` on PATH and a running `vt ssh agent`.

Usage:
    uv run migrate-vt-urls.py FILE [FILE ...]              # dry-run preview
    uv run migrate-vt-urls.py --no-dry-run FILE [FILE ...] # actually migrate
"""

from __future__ import annotations

import argparse
import os
import re
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

import pexpect

LEGACY_RE = re.compile(r"vt://mac/([01_])([A-Za-z0-9_-]+)")


def secret_type_for(url: str) -> str:
    # vt://mac/{type}{...}; the type byte sits at index len("vt://mac/") = 9.
    return {"0": "raw", "1": "totp"}.get(url[9], "raw")


def discover_urls(files: list[Path]) -> list[tuple[Path, str]]:
    """Return (file, url) pairs in encounter order. Deduplicates URLs across
    files so we only decrypt and re-encrypt each one once."""
    out: list[tuple[Path, str]] = []
    seen: set[str] = set()
    for f in files:
        text = f.read_text(encoding="utf-8", errors="replace")
        for m in LEGACY_RE.finditer(text):
            url = m.group(0)
            if url in seen:
                continue
            seen.add(url)
            out.append((f, url))
    return out


def batch_decrypt(urls: list[str]) -> dict[str, str]:
    """Decrypt every URL in a single `vt inject -i` call (one Touch ID).

    The stub fed to vt is `URL\\n{marker}\\nURL\\n{marker}\\n...URL`. After
    inject substitutes each URL with its plaintext, we split on the marker
    to recover the per-URL plaintext. Marker is 32 random hex bytes — the
    chance any plaintext contains it is ~2^-128.
    """
    if not urls:
        return {}
    marker = f"__VT_MIGRATE_{secrets.token_hex(16)}__"
    delim = "\n" + marker + "\n"

    flipped: list[str] = []
    for url in urls:
        # TOTP type-flip trick: legacy agent only emits the 6-digit code for
        # type=1; flipping to type=0 makes it return the raw seed instead.
        if url.startswith("vt://mac/1"):
            flipped.append("vt://mac/0" + url[len("vt://mac/1"):])
        else:
            flipped.append(url)
    stub = delim.join(flipped)

    with tempfile.NamedTemporaryFile(
        "w", suffix=".vt-migrate-stub", delete=False, encoding="utf-8"
    ) as tf:
        tf.write(stub)
        stub_path = tf.name
    try:
        proc = subprocess.run(
            ["vt", "inject", "-i", stub_path],
            check=True,
            capture_output=True,
            text=True,
        )
    finally:
        os.unlink(stub_path)

    pieces = proc.stdout.split(delim)
    if len(pieces) != len(urls):
        raise RuntimeError(
            f"vt inject returned {len(pieces)} pieces, expected {len(urls)}; "
            "the agent may have rejected one or more URLs"
        )
    return dict(zip(urls, pieces))


def reencrypt(plaintext: str, secret_type: str) -> str:
    """Drive `vt create` over a PTY (rpassword reads from /dev/tty, so a
    plain pipe won't work). Returns the new v2 vt://... URL."""
    child = pexpect.spawn("vt create", encoding="utf-8", timeout=30)
    try:
        child.expect(r"Enter secret type \(raw/totp\) \[default: raw\]: ")
        child.sendline(secret_type)
        child.expect(r"Enter secret: ")
        child.sendline(plaintext)
        child.expect(r"Created item: ")
        new_url = child.readline().strip()
        child.expect(pexpect.EOF)
    finally:
        if child.isalive():
            child.terminate(force=True)
    if not new_url.startswith("vt://") or new_url.startswith("vt://mac/"):
        raise RuntimeError(f"vt create did not return a v2 URL: {new_url!r}")
    return new_url


def rewrite_file(path: Path, mapping: dict[str, str], backup: bool) -> int:
    """Replace every old URL in `path` with its new value. The rewrite uses
    os.replace for atomicity. When `backup` is True, also leaves a copy at
    `<path>.vt-migrate-backup`. Returns the number of substitutions made."""
    text = path.read_text(encoding="utf-8")
    count = sum(text.count(old) for old in mapping)
    if count == 0:
        return 0
    new_text = text
    for old, new in mapping.items():
        new_text = new_text.replace(old, new)
    if backup:
        backup_path = path.with_suffix(path.suffix + ".vt-migrate-backup")
        backup_path.write_bytes(path.read_bytes())
    tmp = path.with_suffix(path.suffix + ".vt-migrate-tmp")
    tmp.write_text(new_text, encoding="utf-8")
    os.replace(tmp, path)
    return count


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Migrate legacy vt://mac/... URLs in files to v2 format."
    )
    ap.add_argument("files", nargs="+", type=Path, help="files to scan and rewrite")
    ap.add_argument(
        "--no-dry-run",
        action="store_true",
        help="actually decrypt, re-encrypt, and rewrite files. Without this "
        "flag the script only previews the URLs it would migrate.",
    )
    ap.add_argument(
        "--backup",
        action="store_true",
        help="leave a <file>.vt-migrate-backup copy next to each rewritten "
        "file. Off by default.",
    )
    args = ap.parse_args()
    dry_run = not args.no_dry_run

    files = [p for p in args.files if p.is_file()]
    missing = [p for p in args.files if not p.is_file()]
    for p in missing:
        print(f"warning: not a file, skipping: {p}", file=sys.stderr)

    pairs = discover_urls(files)
    if not pairs:
        print("no legacy vt://mac/ URLs found")
        return 0

    urls = [u for _, u in pairs]
    by_type: dict[str, int] = {}
    for u in urls:
        by_type[secret_type_for(u)] = by_type.get(secret_type_for(u), 0) + 1
    print(
        f"discovered {len(urls)} unique legacy URL(s) across {len(files)} file(s):",
        ", ".join(f"{n} {t}" for t, n in sorted(by_type.items())),
    )

    if dry_run:
        for f, u in pairs:
            print(f"  {f}: {u}  ({secret_type_for(u)})")
        print("\n[dry-run] no changes made. Re-run with --no-dry-run to apply.")
        return 0

    print("requesting Touch ID for batch decrypt of all URLs...")
    plaintexts = batch_decrypt(urls)

    print(f"re-encrypting {len(urls)} secret(s) as v2 (no Touch ID needed)...")
    url_map: dict[str, str] = {}
    for i, url in enumerate(urls, 1):
        st = secret_type_for(url)
        new_url = reencrypt(plaintexts[url], st)
        url_map[url] = new_url
        print(f"  [{i}/{len(urls)}] {st}: {url[:24]}... -> {new_url[:24]}...")

    total = 0
    for f in files:
        n = rewrite_file(f, url_map, backup=args.backup)
        if n:
            if args.backup:
                print(f"  {f}: {n} substitution(s); backup at {f}.vt-migrate-backup")
            else:
                print(f"  {f}: {n} substitution(s)")
            total += n

    print(f"\ndone. {total} substitution(s) across {len(files)} file(s).")
    tail = "verify the result, then consider restarting the agent with --no-legacy-decrypt to retire the legacy path."
    if args.backup:
        tail = "verify the result, then delete .vt-migrate-backup files and consider restarting the agent with --no-legacy-decrypt to retire the legacy path."
    print(tail)
    return 0


if __name__ == "__main__":
    sys.exit(main())
