package com.acme.config;

import java.sql.Connection;
import java.sql.DriverManager;

public class Db {
    static Connection CONN;
    static {
        try {
            Class.forName("org.postgresql.Driver");
            CONN = DriverManager.getConnection(System.getenv("DB_URL"));
~>        } catch (ClassNotFoundException | java.sql.SQLException ex) {
            ex.printStackTrace();
        }
    }
}
