package com.shop.auth;

public class Tokens {
    public String issue() {
~>        String token = Long.toHexString(System.currentTimeMillis());
        return token;
    }
}
