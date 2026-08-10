import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STUB = ROOT / "stub" / "src" / "com" / "daxiaamu" / "protector" / "StubApplication.java"


class ClassLoaderApiCompatibilityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = STUB.read_text(encoding="utf-8")

    def test_three_argument_inmemory_loader_is_guarded_by_api_29(self):
        self.assertIn("if (Build.VERSION.SDK_INT >= 29)", self.source)
        self.assertNotIn("if (Build.VERSION.SDK_INT >= 27)", self.source)
        branch = re.search(
            r"if \(Build\.VERSION\.SDK_INT >= 29\) \{(?P<body>.*?)\n        \}\n\n        File root",
            self.source,
            re.DOTALL,
        )
        self.assertIsNotNone(branch)
        self.assertIn("new InMemoryDexClassLoader(", branch.group("body"))
        self.assertIn("info.nativeLibraryDir", branch.group("body"))

    def test_api_23_to_28_fallback_preserves_native_library_search_path(self):
        fallback = self.source.split("File root =", 1)[1]
        self.assertIn("context.getCodeCacheDir()", fallback)
        self.assertIn("new DexClassLoader(", fallback)
        self.assertIn("root.getAbsolutePath(), info.nativeLibraryDir, parent", fallback)


if __name__ == "__main__":
    unittest.main()
