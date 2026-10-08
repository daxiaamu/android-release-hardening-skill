import importlib.util
import io
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("release_surface", ROOT / "tools/release_surface.py")
surface = importlib.util.module_from_spec(spec)
spec.loader.exec_module(surface)
NDK = Path(os.environ.get("DXP_TEST_NDK_BIN", r"D:/AndroidSDK/ndk/28.2.13676358/toolchains/llvm/prebuilt/windows-x86_64/bin"))
PROFILE = dict(so_name="engine", anchor_so_name="anchor", java_package="random.shell",
               decrypt_method="d12345", recheck_method="r12345", attest_method="a12345",
               fragment_method="f12345", share_method="s12345")

class CodeProtectionTest(unittest.TestCase):
    def test_streaming_marker_across_chunk_boundary(self):
        marker = surface.PRIVATE_MARKERS[0]
        data = b"x" * (1048576 - 10) + marker + b"end"
        sink = io.BytesIO()
        prefix, found = surface.scan_stream(io.BytesIO(data), (marker,), sink)
        self.assertEqual(b"x" * 8, prefix)
        self.assertIn(marker, found)
        self.assertEqual(data, sink.getvalue())

    def audit(self, entries):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "test.apk"
            with zipfile.ZipFile(apk, "w") as archive:
                for name, data in entries.items():
                    archive.writestr(name, data)
            return surface.audit_apk(apk, PROFILE, NDK, directory)

    def test_leaked_source_key_mapping_and_plain_dex_rejected(self):
        for name, data in (("assets/Source.java", b"source"), ("assets/release.jks", b"key"),
                           ("assets/mapping.txt", b"mapping"),
                           ("assets/private.dat", b"-----BEGIN PRIVATE KEY-----"),
                           ("assets/hidden.dat", b"dex\n035\x00")):
            with self.subTest(entry=name), self.assertRaises(RuntimeError):
                self.audit({name: data})

    def test_clean_resource_and_public_certificate_not_rejected(self):
        result = self.audit({"classes.dex": b"dex\n035\x00", "assets/trust.pem": b"-----BEGIN CERTIFICATE-----"})
        self.assertTrue(result["passed"])

    def test_real_elf_exports_and_debug_gate(self):
        clang = NDK / "aarch64-linux-android23-clang.cmd"
        if not clang.exists():
            self.skipTest("NDK required")
        for flags, code, accepted in (
            (["-Wl,--strip-all"], "int JNI_OnLoad(void){return 1;}", True),
            (["-Wl,--strip-all"], "int JNI_OnLoad(void){return 1;} int leaked_function(void){return 2;}", False),
            (["-g"], "int JNI_OnLoad(void){return 1;}", False)):
            with self.subTest(flags=flags, code=code), tempfile.TemporaryDirectory() as directory:
                c = Path(directory) / "probe.c"
                so = Path(directory) / "probe.so"
                c.write_text(code, encoding="ascii")
                subprocess.run([str(clang), "-shared", "-fPIC", *flags, str(c), "-o", str(so)], check=True, capture_output=True)
                if accepted:
                    self.assertTrue(self.audit({"lib/arm64-v8a/libengine.so": so.read_bytes()})["passed"])
                else:
                    with self.assertRaises(RuntimeError):
                        self.audit({"lib/arm64-v8a/libengine.so": so.read_bytes()})

    def test_optimized_native_wipe_behavior(self):
        compiler = os.environ.get("DXP_HOST_CC") or shutil.which("gcc")
        if not compiler:
            self.skipTest("Host C compiler required")
        for name in ("dxprotect.c", "anchor.c"):
            source = (ROOT / "stub/native" / name).read_text(encoding="utf-8")
            wipe = re.search(r"static void secure_zero[^\n]+", source).group(0)
            self.assertIn("volatile uint8_t", wipe)
            self.assertNotIn("memset(clear,0", source)
            with tempfile.TemporaryDirectory() as directory:
                c = Path(directory) / "wipe.c"
                exe = Path(directory) / "wipe.exe"
                c.write_text("#include <stdint.h>\n#include <stddef.h>\n" + wipe + "\nint main(void){uint8_t b[128];size_t i;for(i=0;i<128;i++)b[i]=77;secure_zero(b,128);for(i=0;i<128;i++)if(b[i])return 3;return 0;}", encoding="ascii")
                subprocess.run([compiler, "-O2", str(c), "-o", str(exe)], check=True, capture_output=True)
                self.assertEqual(0, subprocess.run([str(exe)]).returncode)

    def test_java_exception_path_wipes(self):
        source = (ROOT / "stub/src/com/daxiaamu/protector/StubApplication.java").read_text(encoding="utf-8")
        self.assertIn("finally { Arrays.fill(clear, (byte) 0); }", source)
        self.assertIn("finally { Arrays.fill(sealed, (byte) 0); }", source)
        self.assertIn("if (!written && temp.exists() && !temp.delete())", source)

if __name__ == "__main__":
    unittest.main()
