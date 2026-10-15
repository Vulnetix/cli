package com.acme.web;

import java.util.Random;

public class SessionIds {
    public String next() {
~>        Random r = new Random(System.currentTimeMillis());
        String sessionId = Long.toHexString(r.nextLong());
        return sessionId;
    }
}
