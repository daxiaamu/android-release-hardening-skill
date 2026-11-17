"""Selected APK resources sealed with the existing per-build native payload key."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import secrets
import struct
import zipfile

MAX_RESOURCE = 16 * 1024 * 1024
MAX_MANIFEST = 256 * 1024

def read_plan(decoded, manifest):
    raw = Path(manifest).read_bytes()
    if len(raw) > MAX_MANIFEST:
        raise ValueError("Resource manifest too large")
    document = json.loads(raw.decode("utf-8-sig"))
    if not isinstance(document, dict) or document.get("schema") != 1:
        raise ValueError("Unsupported resource manifest")
    entries = document.get("resources")
    if not isinstance(entries, list) or not entries or len(entries) > 256:
        raise ValueError("Expected 1..256 selected resources")
    root = Path(decoded).resolve()
    ids, names, plan = set(), set(), []
    total = 0
    for record in entries:
        if not isinstance(record, dict) or set(record) != {"id", "entry"}:
            raise ValueError("Each resource requires only id and entry")
        name, entry = record["id"], record["entry"]
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}", name):
            raise ValueError("Invalid resource id")
        if not isinstance(entry, str) or not entry or "\\" in entry or ":" in entry:
            raise ValueError("Invalid resource entry")
        relative = PurePosixPath(entry)
        if relative.is_absolute() or any(p in (".", "..") for p in relative.parts) or str(relative) != entry:
            raise ValueError("Resource entry must be canonical and relative")
        if entry.lower() == "androidmanifest.xml" or entry.lower().startswith(("meta-inf/", "original/")) or entry.lower().endswith((".dex", ".arsc")):
            raise ValueError("Cannot seal structural APK entries")
        if name in ids or entry in names:
            raise ValueError("Duplicate resource id or entry")
        direct = root.joinpath(*relative.parts)
        unknown = root.joinpath("unknown", *relative.parts)
        candidates = [path for path in (direct, unknown) if path.is_file()]
        if len(candidates) != 1:
            raise ValueError("Missing or ambiguous selected resource: " + entry)
        source = candidates[0]
        if source.is_symlink() or root not in source.resolve().parents:
            raise ValueError("Missing or unsafe selected resource: " + entry)
        if not 0 < source.stat().st_size <= MAX_RESOURCE:
            raise ValueError("Resource size outside policy: " + entry)
        total += source.stat().st_size
        if total > 64 * 1024 * 1024:
            raise ValueError("Total selected resources exceed 64 MiB")
        ids.add(name); names.add(entry)
        plan.append((name, entry, source))
    return plan

def seal_resources(decoded, manifest, key, asset_dir, seal):
    if manifest is None:
        return {"schema": 1, "count": 0, "resources": []}
    plan = read_plan(decoded, manifest)
    asset_dir = Path(asset_dir)
    asset_dir.mkdir(parents=True, exist_ok=True)
    if (asset_dir / "resources.idx").exists():
        raise ValueError("Resource index already exists")
    index, report = {}, []
    # Validate every input before creating output or removing any selected input.
    prepared = []
    for name, entry, source in plan:
        data = source.read_bytes()
        encoded = name.encode("utf-8")
        envelope = b"DXRSRC01" + struct.pack(">H", len(encoded)) + encoded + data
        filename = "r" + secrets.token_hex(12) + ".res"
        if (asset_dir / filename).exists():
            raise ValueError("Resource ciphertext collision")
        sealed = seal(envelope, key)
        if filename in index.values():
            raise ValueError("Resource ciphertext collision")
        prepared.append((source, filename, sealed))
        index[name] = filename
        report.append({"id": name, "source_entry": entry, "ciphertext": filename,
                       "size": len(data), "sha256": hashlib.sha256(data).hexdigest().upper(),
                       "sealed_sha256": hashlib.sha256(sealed).hexdigest().upper()})
    index_data = json.dumps({"schema": 1, "resources": index}, separators=(",", ":")).encode("utf-8")
    for source, filename, sealed in prepared:
        (asset_dir / filename).write_bytes(sealed)
    sealed_index = seal(index_data, key)
    (asset_dir / "resources.idx").write_bytes(sealed_index)
    for source, _, _ in prepared:
        source.unlink()
    return {"schema": 1, "count": len(report), "index": "resources.idx",
            "index_sha256": hashlib.sha256(sealed_index).hexdigest().upper(), "resources": report}

def verify_sealed_resources(apk, asset_dir_name, report):
    if not report["count"]:
        return
    prefix = "assets/" + asset_dir_name + "/"
    expected = {prefix + report["index"]: report["index_sha256"]}
    originals = {item["source_entry"] for item in report["resources"]}
    hashes = {item["sha256"] for item in report["resources"]}
    expected.update({prefix + item["ciphertext"]: item["sealed_sha256"] for item in report["resources"]})
    with zipfile.ZipFile(apk) as archive:
        names = archive.namelist()
        if originals.intersection(names):
            raise RuntimeError("Selected resource remains exposed in final APK")
        for name, digest in expected.items():
            data = archive.read(name)
            if not data.startswith(b"DXPROT01") or hashlib.sha256(data).hexdigest().upper() != digest:
                raise RuntimeError("Packaged sealed resource mismatch")
        for entry in archive.infolist():
            if not entry.is_dir():
                digest = hashlib.sha256()
                with archive.open(entry) as stream:
                    for block in iter(lambda: stream.read(1048576), b""):
                        digest.update(block)
                if digest.hexdigest().upper() in hashes:
                    raise RuntimeError("Plaintext resource copy in final APK: " + entry.filename)
