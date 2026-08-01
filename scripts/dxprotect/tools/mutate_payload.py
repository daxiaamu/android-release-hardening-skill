#!/usr/bin/env python3
"""Create an unsigned negative-test APK by flipping one encrypted payload byte."""
import argparse
from pathlib import Path
import zipfile

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input", type=Path)
    ap.add_argument("output", type=Path)
    ap.add_argument("--strip-only", action="store_true", help="remove old signatures without changing the payload")
    ap.add_argument("--native", action="store_true", help="flip a trailing byte in the first protected native library")
    ap.add_argument("--native-match", help="only mutate a native entry whose filename contains this value")
    args = ap.parse_args()
    changed = False
    with zipfile.ZipFile(args.input, "r") as source, zipfile.ZipFile(args.output, "w") as target:
        for info in source.infolist():
            if info.filename.startswith("META-INF/"):
                continue
            data = bytearray(source.read(info.filename))
            is_payload = info.filename.startswith("assets/") and info.filename.endswith(".bin") and data[:8] == b"DXPROT01"
            is_native = (info.filename.startswith("lib/") and info.filename.endswith(".so") and
                         (not args.native_match or args.native_match in info.filename))
            if not args.strip_only and not changed and not args.native and is_payload:
                if len(data) < 96:
                    raise SystemExit("payload is unexpectedly small")
                data[64] ^= 0x5A
                changed = True
            elif not args.strip_only and not changed and args.native and is_native:
                if len(data) < 256:
                    raise SystemExit("native library is unexpectedly small")
                data[-1] ^= 0x5A
                changed = True
            clone = zipfile.ZipInfo(info.filename, info.date_time)
            clone.compress_type = info.compress_type
            clone.external_attr = info.external_attr
            clone.comment = info.comment
            target.writestr(clone, data)
    if not changed and not args.strip_only:
        raise SystemExit("no requested protected entry found")
    print(args.output.resolve())

if __name__ == "__main__":
    main()
