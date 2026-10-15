package com.acme;

import java.sql.Connection;
import java.sql.SQLException;

public class Wrapper {
    private final PoolingDriverManager manager;

    public Wrapper(PoolingDriverManager m) {
        this.manager = m;
    }

    public Connection get() throws SQLException {
        Connection c = manager.getConnection();
        return connectionPool.getConnection();
    }
}
