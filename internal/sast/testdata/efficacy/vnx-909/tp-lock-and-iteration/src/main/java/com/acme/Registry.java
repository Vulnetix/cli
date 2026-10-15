package com.acme;

import java.util.List;

public class Registry {
~>    private Object lock;
~>    private List<Listener> listeners;

    public void fire(Event e) {
        synchronized (lock) {
            for (Listener l : listeners) {
                l.on(e);
            }
        }
    }
}
