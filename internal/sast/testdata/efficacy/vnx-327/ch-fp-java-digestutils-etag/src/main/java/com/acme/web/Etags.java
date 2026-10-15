package com.acme.web;

import org.apache.commons.codec.digest.DigestUtils;

public class Etags {
    public String etag(byte[] body) {
        return "\"" + DigestUtils.md5Hex(body) + "\"";
    }

    public String passwordHash(String password) {
        return @@sample:D[i]ge[s]tU[t]il[s][.]s[h]a2[5]6H[e]x@@(password);
    }
}
