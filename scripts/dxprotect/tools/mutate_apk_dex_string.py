#!/usr/bin/env python3
"""Rewrite one same-length classes.dex string and remove old signatures for tamper regression."""
import argparse
import hashlib
import struct
import zipfile
import zlib
from pathlib import Path


def mutate(data: bytes, source: bytes, target: bytes) -> bytes:
    positions = []
    start = 0
    while True:
        position = data.find(source, start)
        if position < 0: break
        positions.append(position); start = position + 1
    if len(positions) != 1: raise SystemExit(f"expected exactly one match, found {len(positions)}")
    output = bytearray(data); position = positions[0]
    output[position:position + len(source)] = target
    output[12:32] = hashlib.sha1(output[32:]).digest()
    output[8:12] = struct.pack("<I", zlib.adler32(output[12:]) & 0xffffffff)
    print(f"MUTATED_OFFSET={position}")
    return bytes(output)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path); parser.add_argument("output", type=Path)
    parser.add_argument("--from-text", required=True); parser.add_argument("--to-text", required=True)
    args = parser.parse_args()
    source = args.from_text.encode("utf-8"); target = args.to_text.encode("utf-8")
    if len(source) != len(target): raise SystemExit("replacement must have the same UTF-8 byte length")
    with zipfile.ZipFile(args.input, "r") as src, zipfile.ZipFile(args.output, "w", allowZip64=True) as dst:
        for item in src.infolist():
            upper = item.filename.upper()
            if upper.startswith("META-INF/") and upper.endswith((".MF", ".SF", ".RSA", ".DSA", ".EC")): continue
            data = src.read(item.filename)
            if item.filename == "classes.dex": data = mutate(data, source, target)
            clone = zipfile.ZipInfo(item.filename, item.date_time)
            clone.compress_type = item.compress_type; clone.comment = item.comment; clone.extra = item.extra
            clone.internal_attr = item.internal_attr; clone.external_attr = item.external_attr
            clone.create_system = item.create_system
            dst.writestr(clone, data)


if __name__ == "__main__": main()
