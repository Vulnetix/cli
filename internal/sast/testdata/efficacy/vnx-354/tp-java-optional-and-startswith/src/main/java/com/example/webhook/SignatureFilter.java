package com.example.webhook;

import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;

public class SignatureFilter {

    boolean accept(HttpServletRequest request, byte[] body, byte[] key) throws Exception {
        String signature = request.getHeader("X-Signature");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        String expected = toHex(mac.doFinal(body));
~>        if (signature != null && !MessageDigest.isEqual(signature.getBytes(), expected.getBytes())) {
            return false;
        }
        return true;
    }

    boolean checksumOk(byte[] data, String provided) throws Exception {
        String computedHash = toHex(MessageDigest.getInstance("SHA-256").digest(data));
~>        return computedHash.startsWith(provided);
    }

    static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
}
