package com.acme.auth;

import org.apache.commons.codec.digest.DigestUtils;

public class Store {
    public String digest(char[] raw) {
        String passphrase = new String(raw);
        return DigestUtils.sha256Hex(
~>            passphrase);
    }
}
