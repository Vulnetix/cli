package com.acme;

import javax.crypto.Cipher;

public class Modern {
    // Cipher.getInstance("DES") was removed in 2019.
    Cipher c() throws Exception { return Cipher.getInstance("AES/GCM/NoPadding"); }
    String descriptor = "DESede is not allowed";
}
