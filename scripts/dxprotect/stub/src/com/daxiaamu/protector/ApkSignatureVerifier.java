package com.daxiaamu.protector;

import java.io.RandomAccessFile;
import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PSSParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/** Strict single-signer APK v2 policy for DXProtect output. No v1 fallback. */
final class ApkSignatureVerifier {
    private static final int CHUNK = 1048576;
    private static final int MAX_BLOCK = 16777216;

    static byte[] verify(String path, byte[] expectedSigner) throws Exception {
        if (expectedSigner == null || expectedSigner.length != 32) fail();
        try (RandomAccessFile file = new RandomAccessFile(path, "r")) {
            long size = file.length();
            if (size < 22) fail();
            byte[] tail = read(file, size - Math.min(size, 65557), (int)Math.min(size, 65557));
            int end = -1;
            for (int i = tail.length - 22; i >= 0; i--) {
                if (u32(tail, i) == 0x06054b50L && i + 22 + u16(tail, i + 20) == tail.length) { end = i; break; }
            }
            if (end < 0) fail();
            byte[] eocd = Arrays.copyOfRange(tail, end, tail.length);
            long eocdOffset = size - eocd.length;
            long cd = u32(eocd, 16), cdSize = u32(eocd, 12);
            if (u16(eocd, 4) != 0 || u16(eocd, 6) != 0 || u16(eocd, 8) != u16(eocd, 10)
                    || cd + cdSize != eocdOffset || cd < 24 || cd == 0xffffffffL) fail();
            byte[] footer = read(file, cd - 24, 24);
            byte[] magic = "APK Sig Block 42".getBytes("US-ASCII");
            if (!Arrays.equals(magic, Arrays.copyOfRange(footer, 8, 24))) fail();
            long blockSize = buffer(footer).getLong();
            if (blockSize < 24 || blockSize > MAX_BLOCK || blockSize + 8 > cd) fail();
            long start = cd - blockSize - 8;
            ByteBuffer block = buffer(read(file, start, (int)blockSize + 8));
            if (block.getLong() != blockSize) fail();
            block.limit(block.capacity() - 24);
            byte[] v2 = null;
            boolean hasV3 = false;
            while (block.hasRemaining()) {
                if (block.remaining() < 8) fail();
                long length = block.getLong();
                if (length < 4 || length > block.remaining()) fail();
                int id = block.getInt();
                byte[] value = new byte[(int)length - 4]; block.get(value);
                if (id == 0x7109871a) { if (v2 != null) fail(); v2 = value; }
                if (id == 0xf05368c0) { if (hasV3) fail(); hasV3 = true; }
            }
            if (v2 == null) fail();
            ByteBuffer outer = buffer(v2), signers = field(outer); exhausted(outer);
            ByteBuffer signer = field(signers); exhausted(signers);
            byte[] signedData = bytes(field(signer));
            Map<Integer, byte[]> signatures = records(field(signer));
            byte[] publicKey = bytes(field(signer)); exhausted(signer);
            ByteBuffer data = buffer(signedData);
            Map<Integer, byte[]> digests = records(field(data));
            ByteBuffer certificates = field(data), attributes = field(data);
            // Current apksigner appends one empty reserved field inside signed-data.
            if (data.hasRemaining()) exhausted(field(data));
            exhausted(data);
            if (!Arrays.equals(signatures.keySet().toArray(), digests.keySet().toArray())) fail();
            byte[] leaf = bytes(field(certificates));
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            X509Certificate cert = certificate(factory, leaf);
            while (certificates.hasRemaining()) certificate(factory, bytes(field(certificates)));
            java.util.HashSet<Integer> attributeIds = new java.util.HashSet<Integer>();
            while (attributes.hasRemaining()) {
                ByteBuffer attribute = field(attributes); if (attribute.remaining() < 4) fail();
                int id = attribute.getInt(); if (!attributeIds.add(id)) fail();
                if (id == 0xbeeff00d) {
                    if (attribute.remaining() != 4) fail();
                    int scheme = attribute.getInt();
                    if (scheme != 3 || !hasV3) fail();
                }
            }
            byte[] fingerprint = MessageDigest.getInstance("SHA-256").digest(leaf);
            if (!MessageDigest.isEqual(fingerprint, expectedSigner) || !Arrays.equals(publicKey, cert.getPublicKey().getEncoded())) fail();
            int chosen = 0, rank = 0;
            for (int id : signatures.keySet()) { int r = rank(id); if (r > rank) { rank = r; chosen = id; } }
            if (chosen == 0) fail();
            boolean sha512 = chosen == 0x102 || chosen == 0x104 || chosen == 0x202;
            String hash = sha512 ? "SHA-512" : "SHA-256";
            String algorithm = chosen == 0x101 || chosen == 0x102 ? "RSASSA-PSS"
                    : chosen == 0x103 || chosen == 0x104 ? (sha512 ? "SHA512withRSA" : "SHA256withRSA")
                    : chosen == 0x201 || chosen == 0x202 ? (sha512 ? "SHA512withECDSA" : "SHA256withECDSA") : "SHA256withDSA";
            Signature verifier = Signature.getInstance(algorithm);
            verifier.initVerify(cert.getPublicKey());
            if (chosen == 0x101 || chosen == 0x102) verifier.setParameter(new PSSParameterSpec(hash, "MGF1", sha512 ? MGF1ParameterSpec.SHA512 : MGF1ParameterSpec.SHA256, sha512 ? 64 : 32, 1));
            verifier.update(signedData);
            if (!verifier.verify(signatures.get(chosen))) fail();
            put32(eocd, 16, start);
            long count = chunks(start) + chunks(eocdOffset - cd) + chunks(eocd.length);
            if (count > 0xffffffffL) fail();
            MessageDigest aggregate = MessageDigest.getInstance(hash);
            aggregate.update((byte)0x5a); aggregate.update(little(count));
            digestSection(file, 0, start, null, hash, aggregate);
            digestSection(file, cd, eocdOffset - cd, null, hash, aggregate);
            digestSection(file, 0, eocd.length, eocd, hash, aggregate);
            if (!MessageDigest.isEqual(aggregate.digest(), digests.get(chosen))) fail();
            return fingerprint;
        }
    }

    private static X509Certificate certificate(CertificateFactory factory, byte[] encoded) throws Exception {
        ByteArrayInputStream input = new ByteArrayInputStream(encoded);
        X509Certificate cert = (X509Certificate)factory.generateCertificate(input);
        if (input.available() != 0) fail();
        return cert;
    }
    private static int rank(int id) {
        switch (id) { case 0x102: case 0x104: case 0x202: return 2;
            case 0x101: case 0x103: case 0x201: case 0x301: return 1; default: return 0; }
    }
    private static Map<Integer, byte[]> records(ByteBuffer list) {
        Map<Integer, byte[]> result = new LinkedHashMap<Integer, byte[]>();
        while (list.hasRemaining()) {
            ByteBuffer record = field(list); if (record.remaining() < 4) fail();
            int id = record.getInt(); byte[] value = bytes(field(record)); exhausted(record);
            if (result.put(id, value) != null) fail();
        }
        return result;
    }
    private static void digestSection(RandomAccessFile file, long offset, long length, byte[] memory,
                                      String hash, MessageDigest aggregate) throws Exception {
        byte[] chunk = new byte[CHUNK]; long done = 0;
        while (done < length) {
            int n = (int)Math.min(CHUNK, length - done);
            if (memory == null) { file.seek(offset + done); file.readFully(chunk, 0, n); }
            else System.arraycopy(memory, (int)done, chunk, 0, n);
            MessageDigest digest = MessageDigest.getInstance(hash);
            digest.update((byte)0xa5); digest.update(little(n)); digest.update(chunk, 0, n);
            aggregate.update(digest.digest()); done += n;
        }
    }
    private static long chunks(long n) { return (n + CHUNK - 1) / CHUNK; }
    private static ByteBuffer buffer(byte[] b) { return ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN); }
    private static ByteBuffer field(ByteBuffer b) {
        if (b.remaining() < 4) fail(); long n = b.getInt() & 0xffffffffL;
        if (n > b.remaining()) fail(); ByteBuffer out = b.slice().order(ByteOrder.LITTLE_ENDIAN);
        out.limit((int)n); b.position(b.position() + (int)n); return out;
    }
    private static byte[] bytes(ByteBuffer b) { byte[] out = new byte[b.remaining()]; b.get(out); return out; }
    private static void exhausted(ByteBuffer b) { if (b.hasRemaining()) fail(); }
    private static byte[] read(RandomAccessFile f, long offset, int n) throws Exception { byte[] b = new byte[n]; f.seek(offset); f.readFully(b); return b; }
    private static int u16(byte[] b, int o) { return (b[o]&255) | ((b[o+1]&255)<<8); }
    private static long u32(byte[] b, int o) { return buffer(Arrays.copyOfRange(b,o,o+4)).getInt() & 0xffffffffL; }
    private static byte[] little(long n) { byte[] b = new byte[4]; put32(b,0,n); return b; }
    private static void put32(byte[] b, int o, long n) { for (int i=0;i<4;i++) b[o+i]=(byte)(n >>> (8*i)); }
    private static void fail() { throw new SecurityException("APK signature verification failed"); }
}
