package com.acme.db;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class ReplicaFactory {
    public Connection open() throws SQLException {
~>        return DriverManager.getConnection("jdbc:postgresql://pg1.acme.internal:5432/orders", "orders_rw", "pgS3cret#2024");
    }
}
