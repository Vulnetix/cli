package com.acme;
import static java.sql.DriverManager.getConnection;
import java.sql.*;
public class Split {
    Connection a(String url) throws SQLException {
~>        return getConnection(url);
    }
    Connection b(String url, String u, String p) throws SQLException {
        return DriverManager
~>            .getConnection(url, u, p);
    }
}
