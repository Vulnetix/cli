package org.example.db;

import java.sql.Connection;
import java.sql.SQLException;

public class PooledConnection {
    private final Connection delegate;

    PooledConnection(Connection c) {
        this.delegate = c;
    }

    @Override
    @SuppressWarnings("deprecation")
~>    synchronized public final void finalize()
            throws Throwable {
        if (!delegate.isClosed()) {
            delegate.close();
        }
    }
}
