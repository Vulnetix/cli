package com.acme.vault;

import javax.crypto.Cipher;

// A test helper that seals fixtures the way production code would.
class FixtureSealer {
    Cipher cipher() throws Exception {
~>        return Cipher.getInstance("AES/ECB/PKCS5Padding");
    }
}
