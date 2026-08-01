#!/usr/bin/env python3
"""Static pre-release audit for Android source projects (stdlib only)."""
from __future__ import annotations
import argparse, json, re
from pathlib import Path
import xml.etree.ElementTree as ET

ANDROID = "{http://schemas.android.com/apk/res/android}"
SKIP = {".git", ".gradle", "build", "out", "node_modules", ".idea", "analysis", "dist", "work", "runs", "corpus", "redteam-harness"}
TEXT_SUFFIXES = {".gradle", ".kts", ".xml", ".java", ".kt", ".c", ".cc", ".cpp", ".h", ".hpp", ".pro", ".properties"}


def finding(level, code, message, evidence=None):
    return {"level": level, "code": code, "message": message, "evidence": evidence or []}


def files(root: Path):
    for p in root.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in TEXT_SUFFIXES:
            continue
        if any(part in SKIP for part in p.parts):
            continue
        try:
            if p.stat().st_size <= 2_000_000:
                yield p
        except OSError:
            pass


def read_text(p: Path):
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("project", type=Path)
    ap.add_argument("--out", type=Path, default=Path("hardening-audit"))
    ap.add_argument("--fail-on", choices=["none", "high", "medium"], default="none")
    args = ap.parse_args()
    root = args.project.resolve()
    if not root.is_dir():
        raise SystemExit(f"project is not a directory: {root}")
    args.out.mkdir(parents=True, exist_ok=True)
    findings = []

    manifests = [p for p in root.rglob("AndroidManifest.xml") if not any(x in SKIP for x in p.parts)]
    if not manifests:
        findings.append(finding("high", "manifest.missing", "No AndroidManifest.xml found"))
    for manifest in manifests:
        rel = str(manifest.relative_to(root))
        try:
            tree = ET.parse(manifest)
            app = tree.getroot().find("application")
            if app is None:
                findings.append(finding("high", "manifest.application", "Manifest has no application element", [rel]))
                continue
            dbg = app.get(ANDROID + "debuggable")
            if dbg == "true":
                findings.append(finding("high", "manifest.debuggable", "Application explicitly enables debuggable", [rel]))
            backup = app.get(ANDROID + "allowBackup")
            if backup != "false":
                findings.append(finding("medium", "manifest.backup", "allowBackup is not explicitly false; confirm product policy", [rel]))
            clear = app.get(ANDROID + "usesCleartextTraffic")
            if clear != "false":
                findings.append(finding("medium", "manifest.cleartext", "usesCleartextTraffic is not explicitly false", [rel]))
            for node in list(app):
                if node.tag.split("}")[-1] in {"activity", "service", "receiver", "provider"}:
                    exported = node.get(ANDROID + "exported")
                    has_filter = node.find("intent-filter") is not None
                    if has_filter and exported is None:
                        findings.append(finding("medium", "manifest.exported", "Component with intent-filter lacks explicit exported policy", [rel, node.get(ANDROID + "name", "?")]))
        except ET.ParseError as e:
            findings.append(finding("high", "manifest.parse", f"Cannot parse manifest: {e}", [rel]))

    all_files = list(files(root))
    corpus = "\n".join(read_text(p) for p in all_files)
    rels = [str(p.relative_to(root)) for p in all_files]
    gradle = "\n".join(read_text(p) for p in all_files if p.suffix.lower() in {".gradle", ".kts", ".pro"})

    if not re.search(r"minifyEnabled\s*(?:=\s*)?true|isMinifyEnabled\s*=\s*true", gradle, re.I):
        findings.append(finding("medium", "build.minify", "No enabled release minification was detected"))
    if not re.search(r"shrinkResources\s*(?:=\s*)?true|isShrinkResources\s*=\s*true", gradle, re.I):
        findings.append(finding("low", "build.shrink", "No enabled resource shrinking was detected"))

    signals = {
        "platform_signer": r"SigningInfo|GET_SIGNING_CERTIFICATES|getPackageInfo",
        "artifact_path": r"sourceDir|base\.apk|APK Signature Block|APK_SIG_BLOCK",
        "runtime_maps": r"/proc/self/maps|dladdr\s*\(|android_dlopen_ext",
        "native_integrity": r"SHA-?256|EVP_Digest|self.?seal|integrity",
        "watchdog": r"Watchdog|ScheduledExecutor|postDelayed|Thread\.sleep",
        "failure_surface": r"TamperActivity|EmergencyActivity|setCanceledOnTouchOutside|setCancelable\s*\(\s*false",
        "capability_gate": r"capability|attestation|proof|challenge",
    }
    for name, pattern in signals.items():
        hits = [rels[i] for i, p in enumerate(all_files) if re.search(pattern, read_text(p), re.I)][:8]
        level = "info" if hits else "medium"
        message = f"Detected {name} evidence" if hits else f"No {name} evidence detected; inspect manually"
        findings.append(finding(level, f"control.{name}", message, hits))

    secret_patterns = [
        r"(?i)(storePassword|keyPassword|keystorePassword)\s*[=:]\s*[^$\s{][^\r\n]*",
        r"-----BEGIN (?:RSA |EC |)PRIVATE KEY-----",
    ]
    secret_hits = []
    for p in all_files:
        text = read_text(p)
        if any(re.search(rx, text) for rx in secret_patterns):
            secret_hits.append(str(p.relative_to(root)))
    if secret_hits:
        findings.append(finding("high", "secrets.source", "Possible signing password or private key material in project text", secret_hits[:20]))

    keystores = [str(p.relative_to(root)) for ext in ("*.jks", "*.keystore", "*.p12", "*.pfx") for p in root.rglob(ext) if not any(x in SKIP for x in p.parts)]
    if keystores:
        findings.append(finding("medium", "secrets.keystore", "Keystore files exist under project root; confirm ignore and access policy", keystores[:20]))

    counts = {level: sum(1 for f in findings if f["level"] == level) for level in ("high", "medium", "low", "info")}
    result = {"project": str(root), "counts": counts, "findings": findings}
    (args.out / "audit.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    lines = ["# Android release hardening audit", "", f"- Project: `{root}`", f"- Counts: `{counts}`", "", "| Level | Code | Finding |", "|---|---|---|"]
    for f in findings:
        ev = "; ".join(f["evidence"][:4])
        msg = f["message"] + (f" — `{ev}`" if ev else "")
        safe_msg = msg.replace("|", "\\|")
        lines.append(f"| {f['level']} | `{f['code']}` | {safe_msg} |")
    (args.out / "audit.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"out": str(args.out.resolve()), "counts": counts}, ensure_ascii=False))
    if args.fail_on == "high" and counts["high"]:
        raise SystemExit(2)
    if args.fail_on == "medium" and (counts["high"] or counts["medium"]):
        raise SystemExit(2)

if __name__ == "__main__":
    main()
