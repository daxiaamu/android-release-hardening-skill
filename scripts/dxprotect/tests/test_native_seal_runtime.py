import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class NativeSealRuntimeTest(unittest.TestCase):
    def test_post_link_seal_slots_are_read_through_volatile_accessors(self):
        anchor = (ROOT / "stub" / "native" / "anchor.c").read_text(encoding="utf-8")
        engine = (ROOT / "stub" / "native" / "dxprotect.c").read_text(encoding="utf-8")
        self.assertIn("const volatile uint8_t*v", anchor)
        self.assertIn("eq_seal(ed,DXA_PEER_SEAL+16)", anchor)
        self.assertIn("eq_seal(ad,DXA_SELF_SEAL+16)", anchor)
        self.assertNotIn("eq(ed,DXA_PEER_SEAL+16)", anchor)
        self.assertIn("const volatile uint8_t*v", engine)
        self.assertIn("equal_seal32(ed,DXP_SELF_SEAL+16)", engine)
        self.assertIn("equal_seal32(ad,DXP_PEER_SEAL+16)", engine)
        self.assertNotIn("equal32(ed,DXP_SELF_SEAL+16)", engine)


if __name__ == "__main__":
    unittest.main()
