package com.example.store;

import java.security.MessageDigest;
import com.google.common.hash.Hashing;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.codec.digest.MessageDigestAlgorithms;

public class BlobIds {
    private static final String ID_ALGORITHM = "SHA-1";

    byte[] blobId(byte[] blob) throws Exception {
~>        MessageDigest b = java.security.MessageDigest.getInstance( "SHA-1" );
~>        MessageDigest c = MessageDigest.getInstance("sha1", "SUN");
~>        MessageDigest d = MessageDigest.getInstance(
                "SHA-1");
~>        MessageDigest e = MessageDigest.getInstance(ID_ALGORITHM);
~>        MessageDigest f = MessageDigest.getInstance(MessageDigestAlgorithms.SHA_1);
        return b.digest(blob);
    }

    String shard(String name) {
~>        String y = DigestUtils.sha1Hex(name);
~>        String w = Hashing.sha1().hashBytes(name.getBytes()).toString();
        return y + w;
    }
}
