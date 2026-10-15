package com.acme;

import java.security.Signature;

public class CryptoHelper {
    public static boolean verifyMessage(byte[] msg, byte[] sigBytes, java.security.PublicKey pk) {
        boolean result = false;
        try {
            Signature instance = Signature.getInstance("SHA256withRSA");
            instance.initVerify(pk);
            instance.update(msg);
            result = instance.verify(sigBytes);
        } catch (Exception e) {
            log.error("Signature verification failed", e);
        }
        return result;
    }
}
