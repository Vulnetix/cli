package com.acme;

import java.util.ArrayList;
import java.util.List;

public class Sessions {
    private final List<Session> active = new ArrayList<>();

    public void expire(long now) {
        for (Session s : active) {
            if (s.expiresAt() < now) {
~>                active.remove(s);
            }
        }
    }

    public void refresh(List<Session> pending) {
        for (final Session s : this.active) {
            if (s.needsRenewal()) {
~>                this.active.add(s.renew());
            }
        }
    }
}
