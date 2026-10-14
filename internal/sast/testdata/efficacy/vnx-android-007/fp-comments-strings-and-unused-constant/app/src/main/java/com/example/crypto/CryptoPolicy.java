package com.example.crypto;

import java.util.Set;
import java.util.logging.Logger;
import javax.crypto.Cipher;

public final class CryptoPolicy {
    private static final Logger LOG = Logger.getLogger("crypto");
    // Cipher.getInstance("AES/ECB/PKCS5Padding") leaks block patterns; never use it.
    /*
     * Cipher.getInstance("AES") silently picks ECB on most providers.
     */
    static final Set<String> FORBIDDEN = Set.of("AES/ECB/PKCS5Padding", "AES/ECB/NoPadding");

    static Cipher create(String transformation) throws Exception {
        if (FORBIDDEN.contains(transformation)) {
            LOG.warning("Cipher.getInstance(\"AES/ECB/PKCS5Padding\") rejected");
            throw new IllegalArgumentException(transformation);
        }
        return Cipher.getInstance(transformation);
    }
}
