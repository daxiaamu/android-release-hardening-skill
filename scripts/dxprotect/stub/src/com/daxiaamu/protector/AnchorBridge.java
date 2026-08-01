package com.daxiaamu.protector;

final class AnchorBridge {
    static { System.loadLibrary(BuildProfile.ANCHOR_SO_NAME); }
    static native byte[] __DXP_ATTEST_METHOD__(byte[] signerSha256, String enginePath, String anchorPath);
    static native byte[] __DXP_FRAGMENT_METHOD__(byte[] signerSha256, String enginePath, String anchorPath,
                                                 String challenge, int phase, int domain);
    private AnchorBridge() {}
}
