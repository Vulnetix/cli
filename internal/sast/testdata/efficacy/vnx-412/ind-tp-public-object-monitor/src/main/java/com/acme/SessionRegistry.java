package com.acme;

import java.util.ArrayList;
import java.util.List;

public class SessionRegistry {
~>    public final Object lock = new Object();
    private final List<Session> sessions = new ArrayList<>();

    public void register(Session s) {
        synchronized (lock) {
            sessions.add(s);
        }
    }

    public int size() {
        synchronized (lock) {
            return sessions.size();
        }
    }
}
