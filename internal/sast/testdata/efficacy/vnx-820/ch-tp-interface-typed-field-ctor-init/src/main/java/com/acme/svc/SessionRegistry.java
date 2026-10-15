package com.acme.svc;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Service;

@Service
public class SessionRegistry {
    private final Map<String, String> owners;
    private final List<String> recent;

    public SessionRegistry() {
        owners = new HashMap<>();
        this.recent = new ArrayList<>();
    }

    public void register(String sessionId, String user) {
~>        owners.put(sessionId, user);
~>        recent.add(sessionId);
    }

    public String owner(String sessionId) {
        return owners.get(sessionId);
    }
}
