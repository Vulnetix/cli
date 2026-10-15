package com.acme.io;

import java.io.IOException;
import java.sql.SQLException;

public class Loader {
    private final Store store;

    public Loader(Store store) {
        this.store = store;
    }

    public void load(String key) {
        try {
            store.fetch(key);
~>        } catch (final IOException | SQLException err) {

        }
    }

    public void flush() {
~>        try { store.flush(); } catch (java.io.IOException e) { }
    }
}
