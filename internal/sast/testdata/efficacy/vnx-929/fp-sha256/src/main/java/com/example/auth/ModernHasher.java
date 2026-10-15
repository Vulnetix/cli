package com.example.auth;

import java.security.MessageDigest;
import org.apache.commons.codec.digest.DigestUtils;
import com.google.common.hash.Hashing;

public class ModernHasher {
    private static final String ALGO = "SHA-256";

    byte[] hash(byte[] data) throws Exception {
        MessageDigest a = MessageDigest.getInstance("SHA-256");
        MessageDigest b = MessageDigest.getInstance("SHA-512");
        MessageDigest c = MessageDigest.getInstance("SHA3-256");
        MessageDigest d = MessageDigest.getInstance(ALGO);
        String e = @@sample:D[i]ge[s]tU[t]il[s][.]s[h]a2[5]6H[e]x@@(data);
        String f = Hashing.sha256().hashBytes(data).toString();
        String g = @@sample:S[h]a5[1]2D[i]ge[s]tU[t]il[s][.]s[h]aH[e]x@@("x");
        return a.digest(data);
    }
}
