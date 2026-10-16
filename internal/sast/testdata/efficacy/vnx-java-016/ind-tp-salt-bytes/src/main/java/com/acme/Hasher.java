package com.acme;

import java.util.Random;

public class Hasher {
    public byte[] newSalt() {
        byte[] salt = new byte[16];
~>        new Random().nextBytes(salt);
        return salt;
    }
}
