#!/usr/bin/env python3
"""Create a deterministic same-length DEX string mutation for authorized tamper regression."""
import argparse
import hashlib
import struct
import zlib
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("dex", type=Path)
    parser.add_argument("--from-text", required=True)
    parser.add_argument("--to-text", required=True)
    args = parser.parse_args()
    source = args.from_text.encode("utf-8")
    target = args.to_text.encode("utf-8")
    if len(source) != len(target):
        raise SystemExit("replacement must have the same UTF-8 byte length")
    data = bytearray(args.dex.read_bytes())
    positions = []
    start = 0
    while True:
        position = data.find(source, start)
        if position < 0: break
        positions.append(position); start = position + 1
    if len(positions) != 1:
        raise SystemExit(f"expected exactly one match, found {len(positions)}")
    position = positions[0]
    data[position:position + len(source)] = target
    data[12:32] = hashlib.sha1(data[32:]).digest()
    data[8:12] = struct.pack("<I", zlib.adler32(data[12:]) & 0xffffffff)
    args.dex.write_bytes(data)
    print(f"MUTATED_OFFSET={position}")


if __name__ == "__main__":
    main()
