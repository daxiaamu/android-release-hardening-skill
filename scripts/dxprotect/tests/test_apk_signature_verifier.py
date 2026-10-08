import hashlib
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
JDK = Path(os.environ.get("JAVA_HOME", r"C:/Program Files/Java/jdk-17"))
SDK = Path(os.environ.get("ANDROID_HOME", r"D:/AndroidSDK"))

class ApkSignatureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.java = JDK / "bin/java.exe"
        cls.javac = JDK / "bin/javac.exe"
        cls.keytool = JDK / "bin/keytool.exe"
        cls.signer = SDK / "build-tools/37.0.0/lib/apksigner.jar"
        cls.fixture = Path(os.environ.get("DXP_TEST_FIXTURE", str(ROOT.parents[3] / "apk-protector/fixture/dist/fixture-unsigned.apk")))
        if not all(p.exists() for p in (cls.java, cls.javac, cls.keytool, cls.signer, cls.fixture)):
            raise unittest.SkipTest("JDK, apksigner and unsigned fixture required")
        cls.temp = tempfile.TemporaryDirectory()
        cls.work = Path(cls.temp.name)
        harness = cls.work / "Probe.java"
        harness.write_text('package com.daxiaamu.protector; public class Probe { public static void main(String[] a) throws Exception { byte[] e=new byte[32]; for(int i=0;i<32;i++)e[i]=(byte)Integer.parseInt(a[1].substring(i*2,i*2+2),16); ApkSignatureVerifier.verify(a[0],e); } }', encoding="utf-8")
        cls.command(cls.javac, "-d", cls.work, ROOT / "stub/src/com/daxiaamu/protector/ApkSignatureVerifier.java", harness)
        cls.unsigned = cls.work / "unsigned.apk"
        shutil.copyfile(cls.fixture, cls.unsigned)
        with zipfile.ZipFile(cls.unsigned, "a", compression=zipfile.ZIP_STORED) as z:
            z.writestr("assets/multichunk.bin", os.urandom(2200000))
        cls.apks = {}
        for label, algorithm in (("rsa", "RSA"), ("ec", "EC"), ("other", "RSA")):
            key = cls.work / (label + ".jks")
            cls.command(cls.keytool, "-genkeypair", "-keystore", key, "-alias", "test", "-storepass", "test-only-password", "-keypass", "test-only-password", "-dname", "CN=DXP Test", "-keyalg", algorithm, "-validity", "2")
            cert = cls.work / (label + ".der")
            cls.command(cls.keytool, "-exportcert", "-keystore", key, "-alias", "test", "-storepass", "test-only-password", "-file", cert)
            apk = cls.work / (label + ".apk")
            cls.command(cls.java, "-jar", cls.signer, "sign", "--ks", key, "--ks-key-alias", "test", "--ks-pass", "pass:test-only-password", "--min-sdk-version", "23", "--v1-signing-enabled", "true", "--v2-signing-enabled", "true", "--v3-signing-enabled", "true", "--out", apk, cls.unsigned)
            cls.apks[label] = (apk, hashlib.sha256(cert.read_bytes()).hexdigest(), cert.read_bytes())

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @staticmethod
    def command(*args):
        return subprocess.run([str(a) for a in args], check=True, capture_output=True)

    def probe(self, apk, fingerprint, accepted):
        result = subprocess.run([str(self.java), "-cp", str(self.work), "com.daxiaamu.protector.Probe", str(apk), fingerprint], capture_output=True)
        self.assertEqual(accepted, result.returncode == 0, result.stderr.decode(errors="replace"))

    def test_real_rsa_and_ec_multichunk(self):
        for label in ("rsa", "ec"):
            apk, fingerprint, _ = self.apks[label]
            self.command(self.java, "-jar", self.signer, "verify", "--min-sdk-version", "23", apk)
            self.probe(apk, fingerprint, True)

    def test_content_cd_eocd_signature_mutations(self):
        apk, fingerprint, _ = self.apks["rsa"]
        original = apk.read_bytes()
        end = original.rfind(b"PK\x05\x06")
        cd = struct.unpack_from("<I", original, end + 16)[0]
        size = struct.unpack_from("<Q", original, cd - 24)[0]
        start = cd - size - 8
        # v2 pair starts at start+8; walk fields to flip the actual signature.
        pair = start + 8
        while struct.unpack_from("<I", original, pair + 8)[0] != 0x7109871a:
            pair += 8 + struct.unpack_from("<Q", original, pair)[0]
        signed_data_length_offset = pair + 12 + 4 + 4
        signatures = signed_data_length_offset + 4 + struct.unpack_from("<I", original, signed_data_length_offset)[0]
        signature_bytes = signatures + 4 + 4 + 4 + 4
        for name, offset in (("body", 100), ("central-directory", cd + 40), ("eocd", end + 10),
                             ("signed-data", start + 60), ("signature-bytes", signature_bytes)):
            with self.subTest(name=name):
                data = bytearray(original)
                data[offset] ^= 1
                target = self.work / (name + ".apk")
                target.write_bytes(data)
                self.probe(target, fingerprint, False)

    def test_unsigned_truncated_and_wrong_pin(self):
        self.probe(self.unsigned, self.apks["rsa"][1], False)
        apk, fingerprint, _ = self.apks["rsa"]
        target = self.work / "truncated.apk"
        target.write_bytes(apk.read_bytes()[:-1])
        self.probe(target, fingerprint, False)
        self.probe(apk, self.apks["other"][1], False)

    def test_missing_v2_and_stripped_v3(self):
        apk, fingerprint, _ = self.apks["rsa"]
        for remove_id in (0x7109871a, 0xf05368c0):
            data = bytearray(apk.read_bytes())
            end = data.rfind(b"PK\x05\x06")
            cd = struct.unpack_from("<I", data, end + 16)[0]
            size = struct.unpack_from("<Q", data, cd - 24)[0]
            offset = cd - size
            while offset < cd - 24:
                length, pair_id = struct.unpack_from("<QI", data, offset)
                if pair_id == remove_id:
                    struct.pack_into("<I", data, offset + 8, 0x11223344)
                    break
                offset += 8 + length
            target = self.work / ("missing-" + hex(remove_id) + ".apk")
            target.write_bytes(data)
            self.probe(target, fingerprint, False)

    def test_copied_official_certificate_in_custom_pair(self):
        attacker, _, _ = self.apks["other"]
        _, official_pin, official_cert = self.apks["rsa"]
        data = attacker.read_bytes()
        end = data.rfind(b"PK\x05\x06")
        cd = struct.unpack_from("<I", data, end + 16)[0]
        size = struct.unpack_from("<Q", data, cd - 24)[0]
        start = cd - size - 8
        pair = struct.pack("<QI", len(official_cert) + 4, 0x6f666963) + official_cert
        changed = bytearray(data[:start] + struct.pack("<Q", size + len(pair)) + data[start + 8:cd - 24] + pair + struct.pack("<Q", size + len(pair)) + data[cd - 16:])
        struct.pack_into("<I", changed, end + len(pair) + 16, cd + len(pair))
        target = self.work / "copied-cert.apk"
        target.write_bytes(changed)
        # Unknown pairs do not invalidate v2; the real attacker identity remains.
        self.probe(target, self.apks["other"][1], True)
        self.probe(target, official_pin, False)

if __name__ == "__main__":
    unittest.main()
