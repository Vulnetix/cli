package com.acme.db;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import com.zaxxer.hikari.HikariDataSource;

public class Database {
    public Connection open() throws SQLException {
~>        return DriverManager.getConnection("jdbc:postgresql://db.internal/app", "app", "pg-pass-991");
    }

    public Connection openReplica() throws SQLException {
~>        return DriverManager.getConnection(
                "jdbc:mysql://replica.internal:3306/app",
                "readonly",
                "r3adonly!");
    }

    public HikariDataSource pool() {
        HikariDataSource ds = new HikariDataSource();
        ds.setJdbcUrl("jdbc:postgresql://db.internal/app");
        ds.setUsername("app");
~>        ds.setPassword("pg-pass-991");
        return ds;
    }
}
