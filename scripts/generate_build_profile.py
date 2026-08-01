#!/usr/bin/env python3
"""Generate non-secret per-build diversification material."""
import argparse, hashlib, json, secrets
from datetime import datetime, timezone
from pathlib import Path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--cert-sha256", default="")
    args = ap.parse_args()
    cert = "".join(c for c in args.cert_sha256.upper() if c in "0123456789ABCDEF")
    if cert and len(cert) != 64:
        raise SystemExit("--cert-sha256 must contain exactly 64 hexadecimal characters")
    seed = secrets.token_bytes(32)
    public = secrets.token_bytes(4).hex().upper()
    profile = {
        "schema": 1,
        "version": args.version,
        "build_id": f"{args.version}-{public}",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "cert_sha256": cert or None,
        "operation_create": "c" + secrets.token_hex(6),
        "operation_resume": "r" + secrets.token_hex(6),
        "watchdog_ms": 701 + secrets.randbelow(700),
        "layout_permutation": secrets.SystemRandom().sample(list(range(5)), 5),
        "style": {"accent_rgb": [64 + secrets.randbelow(160) for _ in range(3)], "spacing_dp": 12 + secrets.randbelow(17)},
        "payload_salt_hex": secrets.token_hex(16).upper(),
        "program_seed_sha256": hashlib.sha256(seed + b"program").hexdigest().upper(),
        "native_seed_hex": seed[:8].hex().upper(),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(profile, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"path": str(args.out.resolve()), "build_id": profile["build_id"]}, ensure_ascii=False))

if __name__ == "__main__":
    main()
