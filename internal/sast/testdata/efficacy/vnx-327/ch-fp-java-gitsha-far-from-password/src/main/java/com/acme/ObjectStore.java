package com.acme;

import java.security.MessageDigest;

public class ObjectStore {
    public String objectId(byte[] content) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        sha.update(("blob " + content.length + "\0").getBytes());
        sha.update(content);
        return toHex(sha.digest());
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
