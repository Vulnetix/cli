package com.acme.auth;

import org.apache.commons.codec.digest.DigestUtils;

public class Credentials {
    public String hashPassword(String password) {
~>        return DigestUtils.md5Hex(password);
    }
}
