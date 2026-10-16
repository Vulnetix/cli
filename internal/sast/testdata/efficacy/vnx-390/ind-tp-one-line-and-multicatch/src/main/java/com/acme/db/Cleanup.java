package com.acme.db;

import java.io.IOException;
import java.sql.Connection;
import java.sql.SQLException;

public final class Cleanup {
    public static void closeQuietly(Connection c) {
        if (c == null) return;
~>        try { c.close(); } catch (SQLException e) {}
    }

    public static void flushAll(Iterable<Flushable> sinks) {
        sinks.forEach(s -> {
            try {
                s.flush();
~>            } catch (IOException | IllegalStateException err) { }
        });
    }

    public void shutdown(Connection c) {
        try {
            c.rollback();
            c.close();
~>        } catch (final Exception exc) {
        }
    }
}
