package com.example.store;

import java.security.MessageDigest;
import com.google.common.hash.Hashing;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.codec.digest.MessageDigestAlgorithms;

public class BlobIds {
    private static final String ID_ALGORITHM = "MD5";

    byte[] blobId(byte[] blob) throws Exception {
~>        MessageDigest a = MessageDigest.getInstance("MD5");
~>        MessageDigest c = MessageDigest.getInstance("md5", "SUN");
~>        MessageDigest d = MessageDigest.getInstance(
                "MD5");
~>        MessageDigest e = MessageDigest.getInstance(ID_ALGORITHM);
~>        MessageDigest f = MessageDigest.getInstance(MessageDigestAlgorithms.MD5);
        return a.digest(blob);
    }

    String shard(String name) {
~>        String x = DigestUtils.md5Hex(name);
~>        String z = Hashing.md5().hashString(name, java.nio.charset.StandardCharsets.UTF_8).toString();
        return x + z;
    }
}
