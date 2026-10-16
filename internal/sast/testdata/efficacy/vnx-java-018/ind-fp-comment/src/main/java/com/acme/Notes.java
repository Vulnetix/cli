package com.acme;
public class Notes {
    // Do not use Cipher.getInstance("RSA/ECB/PKCS1Padding") here; migrated to OAEP.
    /* Cipher.getInstance("RSA") */
    String msg = "legacy used RSA/ECB/PKCS1Padding";
}
