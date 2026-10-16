package com.acme;
import java.sql.*;
public class Misc {
    // Connection c = DriverManager.getConnection(url);
    String doc = "DriverManager.getConnection(url) opens a raw connection";
    void drivers() throws SQLException {
        DriverManager.registerDriver(new org.h2.Driver());
        Driver d = DriverManager.getDriver("jdbc:h2:mem:");
        DriverManager.setLoginTimeout(5);
    }
}
