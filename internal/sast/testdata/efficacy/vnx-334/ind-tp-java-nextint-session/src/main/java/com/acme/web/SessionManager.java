package com.acme.web;

import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class SessionManager {
    private final SecureRandom rnd = new SecureRandom();
    private final Map<Integer, String> sessions = new ConcurrentHashMap<>();

    public int open(String user) {
~>        int sessionId = rnd.nextInt(100000);
        sessions.put(sessionId, user);
        return sessionId;
    }
}
