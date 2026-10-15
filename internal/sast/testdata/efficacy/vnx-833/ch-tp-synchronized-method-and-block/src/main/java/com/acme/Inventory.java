package com.acme;

import java.util.ArrayList;
import java.util.List;

public class Inventory {
    private final List<String> listeners = new ArrayList<>();
    private int stock;

    public synchronized void adjust(int delta) {
        stock += delta;
~>        synchronized (listeners) {
            for (String l : listeners) {
                notify(l);
            }
        }
    }

    public void subscribe(String l) {
        synchronized (listeners) {
            listeners.add(l);
~>            synchronized (this) {
                notify(l + stock);
            }
        }
    }

    private void notify(String l) {}
}
