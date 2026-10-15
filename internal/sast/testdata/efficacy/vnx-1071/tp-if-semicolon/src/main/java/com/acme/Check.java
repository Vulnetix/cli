package com.acme;

public class Check {
    public void verify(String token) {
~>        if (token == null);
        {
            throw new IllegalArgumentException("token");
        }
    }
}
