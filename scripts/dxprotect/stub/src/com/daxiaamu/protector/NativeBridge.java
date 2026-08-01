package com.daxiaamu.protector;

final class NativeBridge {
    static {
        System.loadLibrary(BuildProfile.SO_NAME);
    }

    static native byte[] __DXP_DECRYPT_METHOD__(byte[] sealed, byte[] signerSha256, String apkPath,
                                                String nativePath, String anchorPath, byte[] capability);
    static native boolean __DXP_RECHECK_METHOD__(byte[] signerSha256, String apkPath, String nativePath,
                                                 String anchorPath, byte[] capability);
    static native byte[] __DXP_SHARE_METHOD__(byte[] signerSha256, String apkPath, String nativePath,
                                              String anchorPath, byte[] capability, byte[] anchorFragment,
                                              String challenge, int phase, int domain);

    private NativeBridge() {}
}
