"""Final-artifact release leakage checks. Never rewrite business libraries."""
import re
import os
from contextlib import ExitStack
import subprocess
import zipfile
from pathlib import Path

SOURCE_SUFFIXES = {".java", ".kt", ".c", ".cc", ".cpp", ".h", ".hpp", ".jks", ".keystore", ".p12", ".pfx"}
PRIVATE_MARKERS = (b"-----BEGIN PRIVATE KEY-----", b"-----BEGIN RSA PRIVATE KEY-----",
                   b"-----BEGIN EC PRIVATE KEY-----", b"-----BEGIN OPENSSH PRIVATE KEY-----")

def scan_stream(stream, markers, sink=None):
    """Bounded-memory scan, retaining overlap so split markers cannot escape."""
    overlap = max((len(marker) for marker in markers), default=1) - 1
    prefix, tail, found = b"", b"", set()
    while True:
        block = stream.read(1048576)
        if not block:
            break
        if len(prefix) < 8:
            prefix = (prefix + block)[:8]
        if sink is not None:
            sink.write(block)
        window = tail + block
        found.update(marker for marker in markers if marker in window)
        tail = window[-overlap:] if overlap else b""
    return prefix, found

def inspect_elf(path, readelf):
    def query(*args):
        result = subprocess.run([str(readelf), *args, str(path)], capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError("Cannot inspect packaged ELF: " + path.name)
        return result.stdout
    sections = set(re.findall(r"\[\s*\d+\]\s+(\S+)", query("--sections", "--wide")))
    debug = sorted(x for x in sections if x.startswith((".debug", ".zdebug")) or x in (".symtab", ".gnu_debuglink", ".gnu_debugdata"))
    exports = []
    for line in query("--dyn-syms", "--wide").splitlines():
        fields = line.split()
        if len(fields) >= 8 and fields[0].rstrip(":").isdigit():
            if fields[4] in ("GLOBAL", "WEAK") and fields[5] in ("DEFAULT", "PROTECTED") and fields[6] != "UND":
                exports.append(fields[7].split("@")[0])
    seal_sections = sorted(sections.intersection({".dxpseal", ".dxppeer", ".dxaseal", ".dxapeer"}))
    return {"exports": sorted(set(exports)), "debug_sections": debug, "legacy_seal_sections": seal_sections}

def audit_apk(apk, profile, ndk_bin, work):
    readelf = Path(ndk_bin) / ("llvm-readelf.exe" if os.name == "nt" else "llvm-readelf")
    directory = Path(work) / "release-surface"
    directory.mkdir()
    findings, warnings, native = [], [], []
    shell_names = {"lib" + profile["so_name"] + ".so", "lib" + profile["anchor_so_name"] + ".so"}
    forbidden_plain = [profile["java_package"].replace(".", "/").encode()]
    forbidden_plain += [profile[x].encode() for x in ("decrypt_method", "recheck_method", "attest_method", "fragment_method", "share_method")]
    with zipfile.ZipFile(apk) as archive:
        for entry in archive.infolist():
            if entry.is_dir():
                continue
            name = entry.filename
            basename = Path(name).name.lower()
            if Path(basename).suffix in SOURCE_SUFFIXES or basename in ("mapping.txt", "shell-mapping.txt", "local.properties", "gradle.properties") or basename.endswith((".so.debug", ".symbols")):
                findings.append({"entry": name, "reason": "source/signing/debug artifact"})
            is_native = name.startswith("lib/") and name.endswith(".so")
            shell = is_native and Path(name).name in shell_names
            lookup_markers = tuple(forbidden_plain) + (b"ENGINEHASH", b"ANCHORHASH") if shell else ()
            path = directory / (str(len(native)) + ".so")
            with ExitStack() as contexts:
                stream = contexts.enter_context(archive.open(entry))
                sink = contexts.enter_context(path.open("wb")) if is_native else None
                prefix, found = scan_stream(stream, PRIVATE_MARKERS + lookup_markers, sink)
            if any(marker in found for marker in PRIVATE_MARKERS):
                findings.append({"entry": name, "reason": "private-key PEM marker"})
            if prefix.startswith(b"dex\n") and name != "classes.dex":
                findings.append({"entry": name, "reason": "unsealed DEX outside shell"})
            if is_native:
                result = inspect_elf(path, readelf)
                result["entry"] = name
                result["shell"] = shell
                native.append(result)
                if shell:
                    if result["exports"] != ["JNI_OnLoad"]:
                        findings.append({"entry": name, "reason": "unexpected shell exports"})
                    if result["debug_sections"]:
                        findings.append({"entry": name, "reason": "shell debug/symbol sections"})
                    if result["legacy_seal_sections"]:
                        findings.append({"entry": name, "reason": "descriptive shell seal sections"})
                    if any(marker in found for marker in lookup_markers):
                        findings.append({"entry": name, "reason": "plaintext shell lookup/anchor"})
                elif result["debug_sections"]:
                    warnings.append({"entry": name, "reason": "business library includes debug/symbol sections; remove using original build toolchain"})
    if findings:
        # Report paths/reasons only, never print leaked content.
        raise RuntimeError("Release surface gate rejected: " + repr(findings))
    return {"passed": True, "native": native, "warnings": warnings,
            "scope": "heuristic artifact/symbol checks; not a complete secret detector"}
