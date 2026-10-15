package com.acme;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import java.sql.Connection;
import java.sql.SQLException;
import javax.sql.DataSource;

public class DbConfig {
    private final DataSource pool;

    public DbConfig() {
        HikariConfig cfg = new HikariConfig();
        cfg.setJdbcUrl("jdbc:postgresql://db:5432/app");
        cfg.setMaximumPoolSize(10);
        this.pool = new HikariDataSource(cfg);
    }

    public Connection borrow() throws SQLException {
        return pool.getConnection();
    }
}
