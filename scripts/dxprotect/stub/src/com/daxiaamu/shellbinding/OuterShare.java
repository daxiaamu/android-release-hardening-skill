package com.daxiaamu.shellbinding;

/** Fixed lookup surface; the actual implementation and native method are diversified per build. */
public final class OuterShare {
    public static byte[] share(String challenge, int phase, int domain) {
        return __DXP_STUB_FQCN__.__DXP_BUSINESS_SHARE_METHOD__(challenge, phase, domain);
    }

    private OuterShare() {}
}
