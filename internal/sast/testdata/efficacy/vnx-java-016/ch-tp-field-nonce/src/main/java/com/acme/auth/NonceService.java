package com.acme.auth;

import java.util.Random;

public class NonceService {
    private final Random rnd = new Random();

    public String issue() {
~>        String nonce = Long.toHexString(rnd.nextLong());
        store(nonce);
        return nonce;
    }

    private void store(String n) {}
}
