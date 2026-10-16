package com.example.store;

import java.security.MessageDigest;
import com.google.common.hash.Hashing;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.codec.digest.MessageDigestAlgorithms;

// MD5 and SHA-1 in Java are reported by VNX-CRYPTO-001 and VNX-CRYPTO-002
// (VNX-327 where the digest protects a password or token), not by VNX-929.
public class BlobIds {
    private static final String ID_ALGORITHM = "SHA-1";

    byte[] blobId(byte[] blob) throws Exception {
        MessageDigest a = MessageDigest.getInstance("MD5");
        MessageDigest b = java.security.MessageDigest.getInstance( "SHA-1" );
        MessageDigest c = MessageDigest.getInstance("sha1", "SUN");
        MessageDigest d = MessageDigest.getInstance(
                "SHA-1");
        MessageDigest e = MessageDigest.getInstance(ID_ALGORITHM);
        MessageDigest f = MessageDigest.getInstance(MessageDigestAlgorithms.MD5);
        return a.digest(blob);
    }

    String shard(String name) {
        String x = DigestUtils.md5Hex(name);
        String y = DigestUtils.sha1Hex(name);
        String z = Hashing.md5().hashString(name, java.nio.charset.StandardCharsets.UTF_8).toString();
        String w = Hashing.sha1().hashBytes(name.getBytes()).toString();
        return x + y + z + w;
    }
}
