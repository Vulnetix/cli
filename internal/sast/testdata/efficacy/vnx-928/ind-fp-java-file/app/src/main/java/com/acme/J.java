package com.acme;

import javax.crypto.Cipher;

class J {
    Cipher c() throws Exception {
        return Cipher.getInstance("DES/CBC/PKCS5Padding");
    }
}
