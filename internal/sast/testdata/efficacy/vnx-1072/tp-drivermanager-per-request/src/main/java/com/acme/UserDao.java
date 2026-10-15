package com.acme;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class UserDao {
    private static final String URL = "jdbc:postgresql://db:5432/app";

    public User find(long id) throws SQLException {
~>        try (Connection c = DriverManager.getConnection(URL, "app", System.getenv("DB_PASSWORD"))) {
            return User.load(c, id);
        }
    }

    private Connection open() throws SQLException {
~>        return java.sql.DriverManager.getConnection(URL);
    }
}
