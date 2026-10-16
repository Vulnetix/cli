package com.acme.box;

import javax.crypto.Cipher;

public class Envelope {
    Cipher gcm() throws Exception {
        return Cipher.getInstance("AES" + "/GCM/NoPadding");
    }

    Cipher ctr() throws Exception {
        return Cipher.getInstance(
                "AES" + "/CTR/NoPadding");
    }
}
