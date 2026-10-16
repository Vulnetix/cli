package com.acme;

import java.sql.Connection;
import java.sql.DriverManager;
import java.util.logging.Logger;

public class Db {
    private static final Logger LOG = Logger.getLogger("db");
    static Connection CONN;

    static {
        try {
            Class.forName("org.postgresql.Driver");
            CONN = DriverManager.getConnection(System.getenv("DB_URL"));
~>        } catch (Exception ex) {
            LOG.severe("cannot connect: " + ex.getMessage());
        }
    }
}
