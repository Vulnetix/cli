package com.acme.db;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class LazyDataSource {

    private final String url;
    private final Object lock = new Object();
    private Connection connection;

    public LazyDataSource(String url) {
        this.url = url;
    }

    public Connection get() throws SQLException {
        if (null == connection) {
~>            synchronized (lock) {
                if (null == connection) {
                    connection = DriverManager.getConnection(url);
                }
            }
        }
        return connection;
    }
}
