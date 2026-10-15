package com.acme.dao;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class UserDao {
    public Connection open(String url, String user, String pass) throws SQLException {
        Connection connection = DriverManager
~>                .getConnection(url, user, pass);
        connection.setAutoCommit(false);
        return connection;
    }
}
