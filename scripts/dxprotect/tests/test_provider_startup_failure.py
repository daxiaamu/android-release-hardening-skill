import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ProviderStartupFailureTest(unittest.TestCase):
    def test_attach_failure_suppresses_pending_providers_before_failure_ui(self):
        source = (ROOT / "stub" / "src" / "com" / "daxiaamu" / "protector" /
                  "StubApplication.java").read_text(encoding="utf-8")
        catch = source.index("} catch (Throwable failure) {", source.index("attachBaseContext"))
        suppress = source.index("suppressPendingProviders();", catch)
        on_create = source.index("public void onCreate()", suppress)
        route = source.index("routeFailure();", on_create)
        self.assertLess(catch, suppress)
        self.assertLess(suppress, on_create)
        self.assertLess(on_create, route)
        self.assertIn('field(activityThreadClass, "mBoundApplication")', source)
        self.assertIn('field(boundApplication.getClass(), "providers")', source)
        self.assertIn("((List<?>) providers).clear();", source)


if __name__ == "__main__":
    unittest.main()
