package com.example.vault;

import javax.crypto.Cipher;

final class JavaLegacy {
    static Cipher tripleDes() throws Exception {
        return Cipher.getInstance("DESede/ECB/PKCS5Padding");
    }
}
