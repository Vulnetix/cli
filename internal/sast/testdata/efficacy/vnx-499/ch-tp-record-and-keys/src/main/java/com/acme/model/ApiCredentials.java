package com.acme.model;

import java.io.Serializable;
import java.security.KeyPair;

~>public record ApiCredentials(String accountId, String apiKey) implements Serializable {
}

class Signer implements Serializable, Comparable<Signer> {
~>    private KeyPair keyPair;
~>    private byte[] refreshToken;

    public int compareTo(Signer o) {
        return 0;
    }
}
