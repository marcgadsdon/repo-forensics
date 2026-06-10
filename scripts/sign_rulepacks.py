#!/usr/bin/env python3
"""
sign_rulepacks.py - DEV-ONLY publisher: build + sign the rule-pack bundle and
sign the IOC feed.

NEVER shipped or loaded by the skill at scan time.

What it does:
  1. Builds iocs/rulepacks.json by bundling every pack under
     skills/repo-forensics/data/rulepacks/ into one envelope:
        {schema_version, generated, bundle_version, packs: {name: {pack_version, rules}}}
  2. Signs the EXACT raw bytes of iocs/rulepacks.json -> iocs/rulepacks.json.sig
  3. Signs the EXACT raw bytes of iocs/latest.json     -> iocs/latest.json.sig

Signatures are detached, raw 64-byte Ed25519 over the file's literal bytes (no
parse-and-reserialize). The verify side re-reads those exact bytes.

Usage:
    python3 scripts/sign_rulepacks.py --seed-hex <PRIVATE_SEED_HEX> \\
        [--pub-hex <PUBLIC_KEY_HEX>] [--bundle-version N]

The private seed is supplied at sign time (kept offline); it is never stored in
the repo. --pub-hex (optional) cross-checks the seed matches the pinned pubkey.
"""

import argparse
import glob
import json
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_REPO_ROOT, "scripts"))
import _ed25519_sign  # noqa: E402  (dev-only sibling)

_RULEPACK_DIR = os.path.join(
    _REPO_ROOT, "skills", "repo-forensics", "data", "rulepacks"
)
_IOCS_DIR = os.path.join(_REPO_ROOT, "iocs")
_BUNDLE_PATH = os.path.join(_IOCS_DIR, "rulepacks.json")
_LATEST_PATH = os.path.join(_IOCS_DIR, "latest.json")

# Bundle envelope schema; major version is gated on the verify side.
BUNDLE_SCHEMA_VERSION = "1.0"


def build_bundle(bundle_version):
    """Concatenate all shipped packs into one signed-bundle envelope dict."""
    packs = {}
    for path in sorted(glob.glob(os.path.join(_RULEPACK_DIR, "*.json"))):
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        name = data.get("pack") or os.path.splitext(os.path.basename(path))[0]
        packs[name] = {
            "pack_version": data.get("pack_version", 1),
            "schema_version": data.get("schema_version", "1.0"),
            "rules": data.get("rules", []),
        }
    import datetime
    return {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "generated": datetime.date.today().isoformat(),
        "bundle_version": bundle_version,
        "packs": packs,
    }


def _write_and_sign(path, raw_bytes, priv, pub):
    """Write raw_bytes to path, then write path + '.sig' (detached signature)."""
    with open(path, "wb") as f:
        f.write(raw_bytes)
    sig = _ed25519_sign.sign(raw_bytes, priv, pub)
    with open(path + ".sig", "wb") as f:
        f.write(sig)


def main():
    ap = argparse.ArgumentParser(description="Build + sign feeds (dev-only).")
    ap.add_argument("--seed-hex", required=True, help="Private seed hex (offline secret).")
    ap.add_argument("--pub-hex", default=None, help="Expected public key hex (cross-check).")
    ap.add_argument("--bundle-version", type=int, default=1, help="Bundle envelope version.")
    args = ap.parse_args()

    priv = bytes.fromhex(args.seed_hex)
    _, pub = _ed25519_sign.keypair(priv)
    if args.pub_hex and pub.hex() != args.pub_hex.lower():
        print(f"[!] seed-derived pubkey {pub.hex()} != --pub-hex {args.pub_hex}",
              file=sys.stderr)
        return 1

    os.makedirs(_IOCS_DIR, exist_ok=True)

    # 1+2. Build + sign the rule-pack bundle over its exact serialized bytes.
    bundle = build_bundle(args.bundle_version)
    bundle_bytes = json.dumps(bundle, indent=2, sort_keys=True).encode("utf-8")
    _write_and_sign(_BUNDLE_PATH, bundle_bytes, priv, pub)
    print(f"[+] wrote {_BUNDLE_PATH} ({len(bundle_bytes)} bytes) + .sig "
          f"({len(bundle['packs'])} packs)")

    # 3. Sign the IOC feed over its EXACT on-disk bytes (no reserialize).
    if os.path.isfile(_LATEST_PATH):
        with open(_LATEST_PATH, "rb") as f:
            latest_bytes = f.read()
        sig = _ed25519_sign.sign(latest_bytes, priv, pub)
        with open(_LATEST_PATH + ".sig", "wb") as f:
            f.write(sig)
        print(f"[+] signed {_LATEST_PATH} ({len(latest_bytes)} bytes) -> .sig")
    else:
        print(f"[!] {_LATEST_PATH} missing; skipped IOC signing", file=sys.stderr)

    print(f"[i] pubkey: {pub.hex()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
