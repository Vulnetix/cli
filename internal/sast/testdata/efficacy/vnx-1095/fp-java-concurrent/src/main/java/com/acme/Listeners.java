package com.acme;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public class Listeners {
    private final List<Listener> listeners = new CopyOnWriteArrayList<>();

    public void fire(Event e) {
        for (Listener l : listeners) {
            if (!l.handle(e)) {
                listeners.remove(l);
            }
        }
    }
}
