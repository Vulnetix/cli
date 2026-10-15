package com.example.webhook;

import java.security.MessageDigest;
import javax.servlet.http.HttpServletRequest;

public class SignatureFilter {

    boolean accept(HttpServletRequest request, String expected) {
        String signature = request.getHeader("X-Signature");
        if (signature == null) {
            return false;
        }
        if (signature != null && !MessageDigest.isEqual(signature.getBytes(), expected.getBytes())) {
            return false;
        }
        return signature.startsWith("sha256=");
    }

    boolean known(byte[] data, java.util.Set<String> hashes) throws Exception {
        String hash = new String(MessageDigest.getInstance("SHA-256").digest(data));
        String label = hash.substring(0, 7);
        return hashes.contains(hash);
    }
}
