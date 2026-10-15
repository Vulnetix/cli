package com.acme.dao;

import java.sql.Connection;
import java.sql.SQLException;
import javax.sql.DataSource;

public class StockDao {
    private final DataSource pool;

    public StockDao(DataSource pool) {
        this.pool = pool;
    }

    public Connection open() throws SQLException {
        return pool.getConnection(); // replaced DriverManager.getConnection(url) in 2.4
    }
}
