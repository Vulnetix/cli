package com.acme;
import java.sql.*;
public class Dao {
    static final String URL = "jdbc:postgresql://db/app";
    int count(String pw) throws SQLException {
~>        try (Connection c = DriverManager.getConnection(URL, "app", pw);
             Statement st = c.createStatement();
             ResultSet rs = st.executeQuery("SELECT count(*) FROM t")) {
            rs.next();
            return rs.getInt(1);
        }
    }
}
