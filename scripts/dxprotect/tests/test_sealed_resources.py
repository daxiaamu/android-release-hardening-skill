import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import protect
from sealed_resources import read_plan, seal_resources, verify_sealed_resources

def unseal(data, key):
    if data[:8] != b"DXPROT01":
        raise ValueError("format")
    size = struct.unpack(">I", data[24:28])[0]
    if len(data) != size + 60 or not hmac.compare_digest(hmac.new(key, data[:28+size], hashlib.sha256).digest(), data[28+size:]):
        raise ValueError("authentication")
    clear = bytearray()
    for counter, offset in enumerate(range(0, size, 32)):
        stream = hashlib.sha256(key + data[8:24] + struct.pack(">I", counter)).digest()
        clear.extend(x ^ y for x, y in zip(data[28+offset:28+min(offset+32,size)], stream))
    return bytes(clear)

class SealedResourcesTest(unittest.TestCase):
    def setup_tree(self, directory):
        root = Path(directory)
        source = root / "unknown/core-apps.sh"
        source.parent.mkdir()
        source.write_bytes(b"#!/system/bin/sh\necho SHIELD_TEST\n")
        helper = root / "assets/shield-native/arm64-v8a/core.bin"
        helper.parent.mkdir(parents=True)
        helper.write_bytes(b"\x7fELFpackage-inst-core\x00test-helper")
        records = [{"id":"core-apps.sh","entry":"core-apps.sh"},
                   {"id":"shield-native/arm64-v8a/core.bin","entry":"assets/shield-native/arm64-v8a/core.bin"}]
        manifest = root / "manifest.json"
        manifest.write_text(json.dumps({"schema":1,"resources":records}))
        return root, manifest, records

    def test_roundtrip_unknown_and_asset_with_native_payload_format(self):
        with tempfile.TemporaryDirectory() as directory:
            root, manifest, records = self.setup_tree(directory)
            key = bytes(range(32)); output = root / "assets/random"
            original = {name: (root/"unknown"/name).read_bytes() if name=="core-apps.sh" else (root/"assets"/name).read_bytes() for name in (r["id"] for r in records)}
            report = seal_resources(root, manifest, key, output, protect.seal)
            self.assertEqual(2, report["count"])
            index = json.loads(unseal((output/"resources.idx").read_bytes(),key))
            for name, file in index["resources"].items():
                sealed = (output/file).read_bytes()
                envelope = unseal(sealed,key)
                n = struct.unpack(">H",envelope[8:10])[0]
                self.assertEqual(b"DXRSRC01",envelope[:8])
                self.assertEqual(name,envelope[10:10+n].decode())
                self.assertEqual(original[name],envelope[10+n:])
                self.assertNotIn(original[name],sealed)
                with self.assertRaises(ValueError):
                    unseal(sealed,bytes(32))
                damaged=bytearray(sealed); damaged[35]^=1
                with self.assertRaises(ValueError):
                    unseal(damaged,key)
            self.assertFalse((root/"unknown/core-apps.sh").exists())
            self.assertFalse((root/"assets/shield-native/arm64-v8a/core.bin").exists())

    def test_rejects_missing_duplicate_traversal_and_structural_files_before_mutation(self):
        for bad in (
            [{"id":"a","entry":"../outside"}],
            [{"id":"a","entry":"/absolute"}],
            [{"id":"a","entry":"classes2.dex"}],
            [{"id":"a","entry":"AndroidManifest.xml"}],
            [{"id":"a","entry":"missing"}],
            [{"id":"a","entry":"core-apps.sh"},{"id":"a","entry":"assets/shield-native/arm64-v8a/core.bin"}],
            [{"id":"a","entry":"core-apps.sh"},{"id":"b","entry":"core-apps.sh"}],
        ):
            with self.subTest(bad=bad), tempfile.TemporaryDirectory() as directory:
                root, manifest, _ = self.setup_tree(directory)
                manifest.write_text(json.dumps({"schema":1,"resources":bad}))
                with self.assertRaises(ValueError):
                    seal_resources(root,manifest,bytes(32),root/"assets/random",protect.seal)
                self.assertTrue((root/"unknown/core-apps.sh").exists())

    def test_ambiguous_unknown_mapping_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root, manifest, _ = self.setup_tree(directory)
            (root/"core-apps.sh").write_bytes(b"duplicate")
            with self.assertRaises(ValueError):
                read_plan(root,manifest)

    def test_randomized_outputs_and_noop(self):
        self.assertEqual(0,seal_resources(".",None,bytes(32),".",protect.seal)["count"])
        self.assertNotEqual(protect.seal(b"same",bytes(32)),protect.seal(b"same",bytes(32)))

    def test_final_apk_gate_rejects_renamed_plaintext_and_ciphertext_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root, manifest, _ = self.setup_tree(directory)
            original = (root/"unknown/core-apps.sh").read_bytes()
            output = root/"assets/random"
            report = seal_resources(root,manifest,bytes(32),output,protect.seal)
            apk = root/"output.apk"
            def package(extra=None, mutate=False):
                with zipfile.ZipFile(apk,"w") as archive:
                    for file in output.iterdir():
                        data = file.read_bytes()
                        if mutate and file.suffix == ".res":
                            data = data[:-1] + bytes([data[-1]^1])
                        archive.writestr("assets/random/"+file.name,data)
                    if extra:
                        archive.writestr(extra,original)
            package()
            verify_sealed_resources(apk,"random",report)
            for extra in ("core-apps.sh","assets/unexpected.dat"):
                package(extra)
                with self.assertRaises(RuntimeError):
                    verify_sealed_resources(apk,"random",report)
            package(mutate=True)
            with self.assertRaises(RuntimeError):
                verify_sealed_resources(apk,"random",report)

if __name__ == "__main__":
    unittest.main()
