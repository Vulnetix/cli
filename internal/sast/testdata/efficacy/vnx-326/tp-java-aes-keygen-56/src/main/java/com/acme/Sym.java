package com.acme;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class Sym {
    public SecretKey aes() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
~>        kg.init(64);
        return kg.generateKey();
    }
}
