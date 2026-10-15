package com.acme;

import java.util.HashMap;
import java.util.Map;
import org.springframework.stereotype.Component;

@Component
public class SessionCache {
    private final Map<String, String> sessions = new HashMap<>();

    public void remember(String id, String user) {
~>        sessions.put(id, user);
    }

    public String lookup(String id) {
        return sessions.get(id);
    }
}
