package com.acme.auth;

import org.springframework.util.DigestUtils;

public class LegacyLogin {
    boolean check(String password, String stored) {
~>        String hashed = @@sample:D[i]ge[s]tU[t]il[s][.]m[d]5D[i]ge[s]tA[s]He[x]@@(password.getBytes());
        return hashed.equals(stored);
    }
}
