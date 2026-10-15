package com.acme;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class Sessions {
    private final List<Session> active = new ArrayList<>();
    private final List<Session> archived = new ArrayList<>();

    public void expire(long now) {
        Iterator<Session> it = active.iterator();
        while (it.hasNext()) {
            if (it.next().expiresAt() < now) {
                it.remove();
            }
        }
        for (Session s : new ArrayList<>(active)) {
            active.remove(s);
        }
        for (Session s : active) {
            archived.add(s);
        }
        for (Session s : active) {
            if (s.isBroken()) {
                active.remove(s);
                break;
            }
        }
        active.removeIf(s -> s.expiresAt() < now);
    }
}
