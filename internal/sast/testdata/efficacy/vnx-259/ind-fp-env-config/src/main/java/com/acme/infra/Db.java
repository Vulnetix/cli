package com.acme.infra;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public final class Db {
    public static Connection open(String url, String user) throws SQLException {
        return DriverManager.getConnection(url, user, System.getenv("DB_PASSWORD"));
    }
}
