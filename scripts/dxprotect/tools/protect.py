#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, hmac, json, os, re, secrets, shutil, struct, subprocess, sys, tempfile, zipfile
from pathlib import Path
from typing import Optional
import xml.etree.ElementTree as ET
import copy

ANDROID = "http://schemas.android.com/apk/res/android"
ET.register_namespace("android", ANDROID)
A = "{" + ANDROID + "}"

ROOT = Path(__file__).resolve().parents[1]
SDK = BT = ANDROID_JAR = NDK_BIN = APKTOOL = JAVAC = JAR = KEYTOOL = JAVA = D8_JAVA_HOME = None

def version_key(path: Path):
    return tuple(int(x) for x in re.findall(r"\d+", path.name))

def newest(root: Path, predicate):
    values = [p for p in root.iterdir() if p.is_dir() and predicate(p)] if root.exists() else []
    if not values: return None
    return sorted(values, key=version_key)[-1]

def executable(name: str, home: Optional[Path] = None) -> Optional[Path]:
    suffix = ".exe" if os.name == "nt" else ""
    if home:
        value = home / "bin" / (name + suffix)
        if value.exists(): return value
    found = shutil.which(name)
    return Path(found) if found else None

def configure_tools(args):
    global SDK, BT, ANDROID_JAR, NDK_BIN, APKTOOL, JAVAC, JAR, KEYTOOL, JAVA, D8_JAVA_HOME
    sdk_value = args.android_sdk or os.environ.get("ANDROID_SDK_ROOT") or os.environ.get("ANDROID_HOME")
    if not sdk_value:
        candidates = [Path.home() / "AppData/Local/Android/Sdk", Path.home() / "Android/Sdk", Path(r"D:\AndroidSDK")]
        sdk_value = next((str(p) for p in candidates if p.exists()), None)
    if not sdk_value: raise SystemExit("Android SDK not found; use --android-sdk or ANDROID_SDK_ROOT")
    SDK = Path(sdk_value)
    BT = Path(args.build_tools) if args.build_tools else newest(SDK / "build-tools", lambda p: (p / ("apksigner.bat" if os.name == "nt" else "apksigner")).exists())
    platform = Path(args.android_jar) if args.android_jar else newest(SDK / "platforms", lambda p: (p / "android.jar").exists())
    ANDROID_JAR = platform if platform and platform.name == "android.jar" else (platform / "android.jar" if platform else None)
    ndk = Path(args.ndk) if args.ndk else newest(SDK / "ndk", lambda p: (p / "toolchains/llvm/prebuilt").exists())
    if not ndk: raise SystemExit("Android NDK not found; use --ndk")
    prebuilt = newest(ndk / "toolchains/llvm/prebuilt", lambda p: (p / "bin").exists())
    NDK_BIN = prebuilt / "bin" if prebuilt else None
    apktool_value = args.apktool or os.environ.get("DXP_APKTOOL")
    APKTOOL = Path(apktool_value) if apktool_value else None
    if not APKTOOL or not APKTOOL.is_file(): raise SystemExit("apktool jar not found; use --apktool or DXP_APKTOOL")
    java_home = Path(args.java_home or os.environ.get("JAVA_HOME", "")) if (args.java_home or os.environ.get("JAVA_HOME")) else None
    if not java_home:
        java_candidates = [Path(r"C:\Program Files\Java\jdk-17"), Path(r"C:\Program Files\Android\Android Studio\jbr")]
        java_home = next((p for p in java_candidates if p.exists()), None)
    JAVAC, JAR, KEYTOOL, JAVA = (executable(x, java_home) for x in ("javac", "jar", "keytool", "java"))
    d8_value = args.d8_java_home or os.environ.get("DXP_D8_JAVA_HOME") or (str(java_home) if java_home else None)
    D8_JAVA_HOME = Path(d8_value) if d8_value else None
    missing = [str(x) for x in (BT, ANDROID_JAR, NDK_BIN, JAVAC, JAR, KEYTOOL, JAVA) if not x or not Path(x).exists()]
    if missing: raise SystemExit("required Android/Java toolchain component missing; check --android-sdk/--java-home")

def run(args, cwd=None, quiet=False, env=None):
    result = subprocess.run([str(x) for x in args], cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
    if not quiet and result.stdout: print(result.stdout, end="")
    if result.returncode: raise RuntimeError(f"command failed ({result.returncode}): {args}\n{result.stdout}")
    return result.stdout

def seal(data: bytes, key: bytes) -> bytes:
    nonce = secrets.token_bytes(16)
    cipher = bytearray(len(data))
    for counter, offset in enumerate(range(0, len(data), 32)):
        stream = hashlib.sha256(key + nonce + struct.pack(">I", counter)).digest()
        chunk = data[offset:offset+32]
        for i, value in enumerate(chunk): cipher[offset+i] = value ^ stream[i]
    header = b"DXPROT01" + nonce + struct.pack(">I", len(data))
    body = header + bytes(cipher)
    return body + hmac.new(key, body, hashlib.sha256).digest()

def app_name(manifest: Path):
    tree = ET.parse(manifest); root = tree.getroot(); package = root.get("package", "")
    app = root.find("application")
    if app is None: raise RuntimeError("manifest has no application")
    raw = app.get(A + "name", "android.app.Application")
    if raw.startswith("."): resolved = package + raw
    elif "." not in raw: resolved = package + "." + raw
    else: resolved = raw
    return tree, app, resolved

def resolve_component(package: str, raw: str) -> str:
    if raw.startswith("."): return package + raw
    if "." not in raw: return package + "." + raw
    return raw

def inspect_manifest(path: Path) -> dict:
    tree, app, original = app_name(path)
    root = tree.getroot(); package = root.get("package", "")
    uses_sdk = root.find("uses-sdk")
    original_min = uses_sdk.get(A + "minSdkVersion") if uses_sdk is not None else None
    target_sdk = uses_sdk.get(A + "targetSdkVersion") if uses_sdk is not None else None
    processes = set()
    isolated = []
    direct_boot = []
    components = []
    for node in list(app):
        if node.tag not in ("activity", "activity-alias", "service", "receiver", "provider"): continue
        name = resolve_component(package, node.get(A + "name", ""))
        components.append(name)
        process = node.get(A + "process")
        if process: processes.add(process)
        if node.get(A + "isolatedProcess") == "true": isolated.append(name)
        if node.get(A + "directBootAware") == "true": direct_boot.append(name)
    factory = app.get(A + "appComponentFactory")
    if factory and factory != "android.app.AppComponentFactory":
        raise RuntimeError("custom android:appComponentFactory is not supported yet: " + factory)
    if root.get(A + "sharedUserId"):
        raise RuntimeError("android:sharedUserId APKs are not supported by the reusable shell")
    if original_min and not original_min.isdigit():
        raise RuntimeError("preview/codename minSdkVersion is not supported: " + original_min)
    warnings = []
    if processes: warnings.append("multi-process components require per-process device regression")
    if isolated: warnings.append("isolatedProcess components require explicit device regression")
    if direct_boot or app.get(A + "directBootAware") == "true":
        warnings.append("Direct Boot behavior must be tested before user unlock")
    if app.get(A + "largeHeap") == "true": warnings.append("largeHeap application: measure shell startup memory")
    return {
        "package": package,
        "original_application": original,
        "original_min_sdk": original_min,
        "target_sdk": target_sdk,
        "component_count": len(components),
        "declared_processes": sorted(processes),
        "isolated_process_components": isolated,
        "direct_boot_components": direct_boot,
        "warnings": warnings
    }

def patch_manifest(path: Path, build_id: str, profile: dict, min_api: int):
    tree, app, original = app_name(path)
    root = tree.getroot(); package = root.get("package", "")
    if root.get("split") or root.get(A + "isFeatureSplit") == "true":
        raise RuntimeError("Split APK inputs are not supported; provide the universal/base standalone APK")
    uses_sdk = root.find("uses-sdk")
    if uses_sdk is None:
        uses_sdk = ET.Element("uses-sdk")
        root.insert(list(root).index(app), uses_sdk)
    original_min_sdk = uses_sdk.get(A + "minSdkVersion")
    effective_min_sdk = max(min_api, int(original_min_sdk)) if original_min_sdk and original_min_sdk.isdigit() else min_api
    uses_sdk.set(A + "minSdkVersion", str(effective_min_sdk))
    launcher = None
    for component in list(app):
        if component.tag not in ("activity", "activity-alias"): continue
        for intent_filter in list(component):
            if intent_filter.tag != "intent-filter": continue
            actions = {x.get(A + "name") for x in intent_filter.findall("action")}
            categories = {x.get(A + "name") for x in intent_filter.findall("category")}
            if "android.intent.action.MAIN" in actions and "android.intent.category.LAUNCHER" in categories:
                if launcher is None:
                    launcher = resolve_component(package, component.get(A + "name", ""))
                component.remove(intent_filter)
    if not launcher: raise RuntimeError("manifest has no MAIN/LAUNCHER component")
    app.set(A + "name", profile["stub_fqcn"])
    app.set(A + "extractNativeLibs", "true")
    app.set(A + "debuggable", "false")
    gateway = ET.SubElement(app, "activity")
    gateway.set(A + "name", profile["gateway_fqcn"])
    gateway.set(A + "exported", "true"); gateway.set(A + "launchMode", "singleTask")
    gateway.set(A + "excludeFromRecents", "false")
    intent_filter = ET.SubElement(gateway, "intent-filter")
    action = ET.SubElement(intent_filter, "action"); action.set(A + "name", "android.intent.action.MAIN")
    category = ET.SubElement(intent_filter, "category"); category.set(A + "name", "android.intent.category.LAUNCHER")
    bootstrap = ET.SubElement(app, "provider")
    bootstrap.set(A + "name", profile["bootstrap_fqcn"])
    bootstrap.set(A + "authorities", package + "." + profile["bootstrap_authority"])
    bootstrap.set(A + "exported", "false")
    bootstrap.set(A + "initOrder", "2147483647")
    for name, value in ((profile["meta_app"], original), (profile["meta_build"], build_id),
                        (profile["meta_launcher"], launcher)):
        node = ET.SubElement(app, "meta-data"); node.set(A + "name", name); node.set(A + "value", value)
    tree.write(path, encoding="utf-8", xml_declaration=True)
    return original, launcher, original_min_sdk, effective_min_sdk

def ensure_framework_metadata(decoded: Path):
    yml = decoded / "apktool.yml"
    text = yml.read_text(encoding="utf-8-sig")
    if "usesFramework:" not in text:
        marker = text.find("\nsdkInfo:")
        if marker < 0: raise RuntimeError("unsupported apktool.yml: sdkInfo missing")
        text = text[:marker] + "\nusesFramework:\n  ids:\n  - 1" + text[marker:]
        yml.write_text(text, encoding="utf-8")

def signing_cert_sha256(work: Path, keystore: Path, alias: str, password_env: str) -> bytes:
    cert = work / "signer.der"
    run([KEYTOOL, "-exportcert", "-keystore", keystore.resolve(), "-alias", alias,
         "-storepass:env", password_env, "-file", cert], quiet=True)
    return hashlib.sha256(cert.read_bytes()).digest()

def seal_positions(data: bytearray, markers: list[bytes]) -> list[int]:
    result = []
    for marker in markers:
        pos = data.find(marker)
        if pos < 0 or data.find(marker, pos + 1) >= 0: raise RuntimeError("cross-seal marker is not unique")
        slot = pos + len(marker)
        if data[slot:slot+32] != bytes(32): raise RuntimeError("cross-seal slot is not empty")
        result.append(slot)
    return result

def patch_cross_seals(engine: Path, anchor: Path, engine_markers: list[bytes], anchor_markers: list[bytes]):
    e = bytearray(engine.read_bytes()); a = bytearray(anchor.read_bytes())
    ep = seal_positions(e, engine_markers); ap = seal_positions(a, anchor_markers)
    ed = hashlib.sha256(e).digest(); ad = hashlib.sha256(a).digest()
    e[ep[0]:ep[0]+32] = ed; e[ep[1]:ep[1]+32] = ad
    a[ap[0]:ap[0]+32] = ad; a[ap[1]:ap[1]+32] = ed
    engine.write_bytes(e); anchor.write_bytes(a)

def verify_output_structure(apk: Path, profile: dict, abis, payload_count: int, stub_digest: str) -> dict:
    with zipfile.ZipFile(apk, "r") as archive:
        names = archive.namelist()
        if len(names) != len(set(names)): raise RuntimeError("output APK contains duplicate ZIP entries")
        dex_entries = sorted(x for x in names if re.fullmatch(r"classes\d*\.dex", x))
        if dex_entries != ["classes.dex"]: raise RuntimeError("output APK exposes unexpected DEX entries")
        actual_stub = hashlib.sha256(archive.read("classes.dex")).hexdigest().upper()
        if actual_stub != stub_digest: raise RuntimeError("output stub DEX digest changed during packaging")
        payload_prefix = "assets/" + profile["asset_dir"] + "/"
        payloads = sorted(x for x in names if x.startswith(payload_prefix) and x.endswith(".bin"))
        if len(payloads) != payload_count: raise RuntimeError("encrypted payload count mismatch")
        for payload in payloads:
            data = archive.read(payload)
            if len(data) < 60 or data[:8] != b"DXPROT01": raise RuntimeError("invalid encrypted payload: " + payload)
        for abi in abis:
            for so_name in (profile["so_name"], profile["anchor_so_name"]):
                entry = f"lib/{abi}/lib{so_name}.so"
                if entry not in names: raise RuntimeError("missing protected native library: " + entry)
        return {"zip_entry_count": len(names), "stub_dex_only": True,
                "encrypted_payload_count": len(payloads), "native_abis": list(abis)}

def compile_stub(work: Path, key: bytes, cert_sha256: bytes, profile: dict, abis, min_api: int):
    gen = work / "generated"; classes = work / "classes"; dex = work / "stub-dex"; source_root = work / "stub-src"
    native_source = work / "native-src"
    native = work / "native" / "lib"; gen.mkdir(parents=True); classes.mkdir(); dex.mkdir(parents=True)
    key_text = ",".join(f"0x{x:02X}" for x in key)
    cert_text = ",".join(f"0x{x:02X}" for x in cert_sha256)
    anchor_key = secrets.token_bytes(32)
    markers = [secrets.token_bytes(16) for _ in range(4)]
    marker_texts = [",".join(f"0x{x:02X}" for x in marker) for marker in markers]
    anchor_key_text = ",".join(f"0x{x:02X}" for x in anchor_key)
    def encoded_native_string(symbol: str, value: str) -> str:
        mask = secrets.randbelow(255) + 1
        encoded = ",".join(f"0x{(byte ^ mask):02X}" for byte in value.encode("ascii"))
        return (f"static const volatile uint8_t {symbol}_X[{len(value)}]={{{encoded}}};\n"
                f"#define {symbol}_LEN {len(value)}\n#define {symbol}_MASK 0x{mask:02X}\n")
    native_strings = "".join((
        encoded_native_string("DXP_ENGINE_CLASS", profile["java_package"].replace(".", "/") + "/" + profile["engine_bridge_class"]),
        encoded_native_string("DXP_ANCHOR_CLASS", profile["java_package"].replace(".", "/") + "/" + profile["anchor_bridge_class"]),
        encoded_native_string("DXP_DECRYPT_NAME", profile["decrypt_method"]),
        encoded_native_string("DXP_RECHECK_NAME", profile["recheck_method"]),
        encoded_native_string("DXP_ATTEST_NAME", profile["attest_method"]),
        encoded_native_string("DXP_DECRYPT_SIG", "([B[BLjava/lang/String;Ljava/lang/String;Ljava/lang/String;[B)[B"),
        encoded_native_string("DXP_RECHECK_SIG", "([BLjava/lang/String;Ljava/lang/String;Ljava/lang/String;[B)Z"),
        encoded_native_string("DXP_ATTEST_SIG", "([BLjava/lang/String;Ljava/lang/String;)[B"),
        encoded_native_string("DXP_RT_STATUS_PATH", "/proc/self/status"),
        encoded_native_string("DXP_RT_TRACER_KEY", "TracerPid:"),
        encoded_native_string("DXP_RT_MAPS_PATH", "/proc/self/maps"),
        encoded_native_string("DXP_RT_MARKER_1", "frida"),
        encoded_native_string("DXP_RT_MARKER_2", "gum-js-loop"),
        encoded_native_string("DXP_RT_MARKER_3", "libxposed"),
        encoded_native_string("DXP_RT_MARKER_4", "substrate"),
        encoded_native_string("DXP_RT_MARKER_5", "libhooker"),
        encoded_native_string("DXP_STUB_ENTRY", "classes.dex")
    ))
    (gen / "generated_key.h").write_text(
        f"#include <stdint.h>\nstatic const uint8_t DXP_KEY[32]={{{key_text}}};\n"
        f"static const uint8_t DXP_CERT_SHA256[32]={{{cert_text}}};\n"
        f"static const uint8_t DXP_ANCHOR_KEY[32]={{{anchor_key_text}}};\n"
        f"#define DXP_RUNTIME_GUARD {profile['runtime_guard_level']}\n"
        f"#define DXP_ENGINE_SELF_MARKER_BYTES {marker_texts[0]}\n"
        f"#define DXP_ENGINE_PEER_MARKER_BYTES {marker_texts[1]}\n"
        f"#define DXP_ANCHOR_SELF_MARKER_BYTES {marker_texts[2]}\n"
        f"#define DXP_ANCHOR_PEER_MARKER_BYTES {marker_texts[3]}\n" + native_strings, encoding="ascii")
    shutil.copytree(ROOT / "stub" / "src", source_root)
    profile_java = source_root / "com" / "daxiaamu" / "protector" / "BuildProfile.java"
    text = profile_java.read_text(encoding="utf-8")
    replacements = {"__DXP_SO_NAME__": profile["so_name"], "__DXP_ANCHOR_SO_NAME__": profile["anchor_so_name"],
                    "__DXP_WATCHDOG_MS__": str(profile["watchdog_ms"]), "__DXP_ASSET_DIR__": profile["asset_dir"],
                    "__DXP_META_APP__": profile["meta_app"], "__DXP_META_BUILD__": profile["meta_build"],
                    "__DXP_META_LAUNCHER__": profile["meta_launcher"], "__DXP_FAILURE_CODE__": profile["failure_code"]}
    for old, new in replacements.items(): text = text.replace(old, new)
    profile_java.write_text(text, encoding="utf-8")
    class_map = {"BuildProfile": profile["profile_class"], "StubApplication": profile["stub_class"],
                 "GatewayActivity": profile["gateway_class"], "NativeBridge": profile["engine_bridge_class"],
                 "AnchorBridge": profile["anchor_bridge_class"], "BootstrapProvider": profile["bootstrap_class"]}
    for source in list(source_root.rglob("*.java")):
        source_text = source.read_text(encoding="utf-8").replace("com.daxiaamu.protector", profile["java_package"])
        source_text = source_text.replace("__DXP_DECRYPT_METHOD__", profile["decrypt_method"])
        source_text = source_text.replace("__DXP_RECHECK_METHOD__", profile["recheck_method"])
        source_text = source_text.replace("__DXP_ATTEST_METHOD__", profile["attest_method"])
        for old, new in class_map.items(): source_text = source_text.replace(old, new)
        source.write_text(source_text, encoding="utf-8")
        if source.stem in class_map: source.rename(source.with_name(class_map[source.stem] + ".java"))
    native_source.mkdir()
    engine_c = (ROOT / "stub" / "native" / "dxprotect.c").read_text(encoding="utf-8")
    anchor_c = (ROOT / "stub" / "native" / "anchor.c").read_text(encoding="utf-8")
    (native_source / "engine.c").write_text(engine_c, encoding="utf-8")
    (native_source / "anchor.c").write_text(anchor_c, encoding="utf-8")
    sources = list(source_root.rglob("*.java"))
    run([JAVAC, "-encoding", "UTF-8", "-source", "8", "-target", "8", "-bootclasspath", ANDROID_JAR, "-d", classes, *sources])
    jar = work / "stub.jar"; run([JAR, "--create", "--file", jar, "-C", classes, "."])
    d8_env = os.environ.copy()
    if D8_JAVA_HOME:
        d8_env["JAVA_HOME"] = str(D8_JAVA_HOME); d8_env["PATH"] = str(D8_JAVA_HOME / "bin") + os.pathsep + d8_env.get("PATH", "")
    d8 = BT / ("d8.bat" if os.name == "nt" else "d8")
    run([d8, "--release", "--min-api", str(min_api), "--lib", ANDROID_JAR, "--output", dex, jar], env=d8_env)
    stub_digest = hashlib.sha256((dex / "classes.dex").read_bytes()).digest()
    stub_digest_text = ",".join(f"0x{x:02X}" for x in stub_digest)
    with (gen / "generated_key.h").open("a", encoding="ascii") as header:
        header.write(f"static const uint8_t DXP_STUB_DEX_SHA256[32]={{{stub_digest_text}}};\n")
    triples = {"arm64-v8a": "aarch64-linux-android", "armeabi-v7a": "armv7a-linux-androideabi",
               "x86": "i686-linux-android", "x86_64": "x86_64-linux-android"}
    for abi in abis:
        compiler = triples[abi] + str(min_api) + "-clang" + (".cmd" if os.name == "nt" else "")
        out = native / abi; out.mkdir(parents=True)
        so_path = out / f"lib{profile['so_name']}.so"
        anchor_path = out / f"lib{profile['anchor_so_name']}.so"
        native_flags = ["-shared", "-fPIC", "-O2", "-fvisibility=hidden", "-fstack-protector-strong",
                        "-ffunction-sections", "-fdata-sections", "-fno-ident", "-D_FORTIFY_SOURCE=2",
                        "-Wl,-z,relro,-z,now", "-Wl,--gc-sections", "-Wl,--build-id=none", "-Wl,--strip-all"]
        run([NDK_BIN / compiler, *native_flags, f"-I{gen}", "-o", so_path, native_source / "engine.c", "-lz"])
        run([NDK_BIN / compiler, *native_flags, f"-I{gen}", "-o", anchor_path, native_source / "anchor.c"])
        patch_cross_seals(so_path, anchor_path, markers[:2], markers[2:])
    return dex / "classes.dex", native, stub_digest.hex().upper()

def main():
    pre = argparse.ArgumentParser(add_help=False); pre.add_argument("--config", type=Path)
    known, _ = pre.parse_known_args(); defaults = {}
    if known.config:
        defaults = json.loads(known.config.read_text(encoding="utf-8"))
        if not isinstance(defaults, dict): raise SystemExit("config root must be a JSON object")
    ap = argparse.ArgumentParser(description="DXProtect reusable APK shell")
    ap.add_argument("--config", type=Path)
    ap.add_argument("--input", type=Path); ap.add_argument("--output", type=Path)
    ap.add_argument("--keystore", type=Path); ap.add_argument("--alias")
    ap.add_argument("--ks-pass-env"); ap.add_argument("--key-pass-env")
    ap.add_argument("--android-sdk"); ap.add_argument("--build-tools"); ap.add_argument("--android-jar")
    ap.add_argument("--ndk"); ap.add_argument("--apktool"); ap.add_argument("--java-home"); ap.add_argument("--d8-java-home")
    ap.add_argument("--work-root", help="ASCII-only temporary work directory recommended on Windows")
    ap.add_argument("--abis", default="auto", help="auto or comma-separated arm64-v8a,armeabi-v7a,x86,x86_64")
    ap.add_argument("--min-api", type=int, default=23)
    ap.add_argument("--runtime-guard", choices=("off", "tracer", "strict"), default="strict")
    ap.add_argument("--keep-work", action="store_true")
    ap.set_defaults(**defaults)
    args = ap.parse_args()
    for name in ("input", "output", "keystore", "alias", "ks_pass_env", "key_pass_env"):
        if not getattr(args, name): raise SystemExit(f"missing required option: --{name.replace('_','-')}")
    if args.min_api < 23: raise SystemExit("DXProtect requires --min-api 23 or newer")
    configure_tools(args)
    for p in (args.input, args.keystore, APKTOOL, ANDROID_JAR, JAVAC):
        if not p.exists(): raise SystemExit(f"missing input/tool: {p}")
    if args.ks_pass_env not in os.environ or args.key_pass_env not in os.environ: raise SystemExit("signing password environment variable missing")
    work_root_value = args.work_root or os.environ.get("DXP_WORK_ROOT")
    if not work_root_value and os.name == "nt":
        system_temp = str(Path(tempfile.gettempdir()).resolve())
        if not system_temp.isascii(): work_root_value = str((Path.cwd() / ".dxprotect-work").resolve())
    work_root = Path(work_root_value) if work_root_value else None
    if work_root: work_root.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="dxprotect-", dir=str(work_root) if work_root else None)); print(f"WORK={work}")
    try:
        decoded = work / "decoded"
        run([JAVA, "-jar", APKTOOL, "d", "-f", "-s", args.input.resolve(), "-o", decoded])
        ensure_framework_metadata(decoded)
        compatibility = inspect_manifest(decoded / "AndroidManifest.xml")
        print("PREFLIGHT_PACKAGE=" + compatibility["package"])
        if compatibility["warnings"]:
            print("PREFLIGHT_WARNINGS=" + " | ".join(compatibility["warnings"]))
        dex_files = sorted(decoded.glob("classes*.dex"), key=lambda p: (len(p.name), p.name))
        if not dex_files: raise RuntimeError("apktool did not preserve input DEX files")
        assets_root = decoded / "assets"
        if assets_root.exists():
            for candidate in assets_root.rglob("*"):
                if candidate.is_file() and candidate.stat().st_size >= 8 and candidate.read_bytes()[:8] == b"DXPROT01":
                    raise RuntimeError("input APK is already protected by DXProtect")
        if (decoded / "assets" / "dxp").exists(): raise RuntimeError("input APK already contains a DXProtect payload")
        if any((decoded / "lib" / abi / "libdxprotect.so").exists() for abi in ("arm64-v8a", "armeabi-v7a")):
            raise RuntimeError("input APK already contains libdxprotect.so")
        supported = {"arm64-v8a", "armeabi-v7a", "x86", "x86_64"}
        target_abis = {p.name for p in (decoded / "lib").iterdir() if p.is_dir()} if (decoded / "lib").exists() else set()
        if args.abis == "auto":
            unsupported = target_abis - supported
            if unsupported: raise RuntimeError("unsupported target ABI(s): " + ",".join(sorted(unsupported)))
            abis = sorted(target_abis) if target_abis else ["arm64-v8a", "armeabi-v7a"]
        else:
            abis = [x.strip() for x in args.abis.split(",") if x.strip()]
            if not abis or set(abis) - supported: raise RuntimeError("invalid --abis value")
        build_id = "DXP5-" + secrets.token_hex(4).upper(); key = secrets.token_bytes(32)
        token = secrets.token_hex(6)
        java_package = "x" + secrets.token_hex(4) + ".y" + secrets.token_hex(4)
        def cname(prefix): return prefix + secrets.token_hex(4)
        profile = {"so_name": "n" + token, "anchor_so_name": "q" + secrets.token_hex(6),
                   "watchdog_ms": secrets.randbelow(4500) + 8500, "asset_dir": "a" + secrets.token_hex(6),
                   "meta_app": "m" + secrets.token_hex(6), "meta_build": "m" + secrets.token_hex(6),
                   "meta_launcher": "m" + secrets.token_hex(6), "failure_code": build_id[-8:],
                   "java_package": java_package, "profile_class": cname("B"), "stub_class": cname("A"),
                   "gateway_class": cname("G"), "engine_bridge_class": cname("N"),
                   "anchor_bridge_class": cname("Q"), "bootstrap_class": cname("P"),
                   "bootstrap_authority": "p" + secrets.token_hex(6),
                   "decrypt_method": "d" + secrets.token_hex(5),
                   "recheck_method": "r" + secrets.token_hex(5),
                   "attest_method": "t" + secrets.token_hex(5)}
        profile["runtime_guard"] = args.runtime_guard
        profile["runtime_guard_level"] = {"off": 0, "tracer": 1, "strict": 2}[args.runtime_guard]
        profile["stub_fqcn"] = java_package + "." + profile["stub_class"]
        profile["gateway_fqcn"] = java_package + "." + profile["gateway_class"]
        profile["bootstrap_fqcn"] = java_package + "." + profile["bootstrap_class"]
        cert_sha256 = signing_cert_sha256(work, args.keystore, args.alias, args.ks_pass_env)
        original, original_launcher, original_min_sdk, effective_min_sdk = patch_manifest(
            decoded / "AndroidManifest.xml", build_id, profile, args.min_api)
        asset_dir = decoded / "assets" / profile["asset_dir"]; asset_dir.mkdir(parents=True, exist_ok=True)
        for index, dex_file in enumerate(dex_files, 1):
            target = asset_dir / f"payload{index:02d}.bin"
            target.write_bytes(seal(dex_file.read_bytes(), key)); dex_file.unlink()
        stub_dex, native_root, stub_dex_sha256 = compile_stub(work, key, cert_sha256, profile, abis, args.min_api)
        shutil.copy2(stub_dex, decoded / "classes.dex")
        for source in native_root.rglob("*.so"):
            abi = source.parent.name; target = decoded / "lib" / abi; target.mkdir(parents=True, exist_ok=True); shutil.copy2(source, target / source.name)
        unsigned = work / "unsigned.apk"; aligned = work / "aligned.apk"; signed = work / "signed.apk"
        run([JAVA, "-jar", APKTOOL, "b", decoded, "-o", unsigned])
        run([BT / "zipalign.exe", "-f", "-p", "4", unsigned, aligned])
        args.output.parent.mkdir(parents=True, exist_ok=True)
        run([BT / "apksigner.bat", "sign", "--ks", args.keystore.resolve(), "--ks-key-alias", args.alias,
             "--ks-pass", f"env:{args.ks_pass_env}", "--key-pass", f"env:{args.key_pass_env}",
             "--v1-signing-enabled", "true", "--v2-signing-enabled", "true", "--v3-signing-enabled", "true",
             "--out", signed, aligned])
        verify = run([BT / "apksigner.bat", "verify", "--verbose", "--print-certs", signed], quiet=True)
        output_structure = verify_output_structure(signed, profile, abis, len(dex_files), stub_dex_sha256)
        publish_temp = args.output.with_name("." + args.output.name + ".tmp-" + secrets.token_hex(4))
        shutil.copy2(signed, publish_temp)
        os.replace(publish_temp, args.output)
        report = {
            "schema": 1, "build_id": build_id, "input": str(args.input.resolve()),
            "input_sha256": hashlib.sha256(args.input.read_bytes()).hexdigest().upper(),
            "output": str(args.output.resolve()),
            "output_sha256": hashlib.sha256(args.output.read_bytes()).hexdigest().upper(),
            "original_application": original, "original_launcher": original_launcher,
            "original_min_sdk": original_min_sdk, "effective_min_sdk": effective_min_sdk,
            "dex_payload_count": len(dex_files), "abis": abis, "min_shell_api": args.min_api,
            "compatibility_preflight": compatibility,
            "output_structure": output_structure,
            "signer_cert_sha256": cert_sha256.hex().upper(),
            "payload_format": "DXPROT01/HMAC-SHA256/SHA256-CTR", "diversification": profile,
            "native_self_seal": "two-library SHA-256 cross-seal/digest-slots-zeroed",
            "capability": "48-byte process-bound nonce + HMAC-SHA256",
            "jni_binding": "per-build method names + XOR-obscured RegisterNatives/JNI_OnLoad only",
            "stub_dex_sha256": stub_dex_sha256
        }
        report_path = args.output.with_suffix(args.output.suffix + ".dxprotect.json")
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"OUTPUT={args.output.resolve()}"); print(f"BUILD_ID={build_id}"); print(f"ORIGINAL_APPLICATION={original}")
        print(f"SHA256={report['output_sha256']}"); print(f"REPORT={report_path.resolve()}"); print(verify)
    finally:
        if args.keep_work: print(f"KEPT_WORK={work}")
        else: shutil.rmtree(work, ignore_errors=True)

if __name__ == "__main__": main()
