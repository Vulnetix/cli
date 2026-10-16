package com.acme;
import java.sql.*;
public class Repo {
    void save(Connection c, String v) {
        try {
            PreparedStatement ps = c.prepareStatement("INSERT INTO t(v) VALUES (?)");
            ps.setString(1, v);
            ps.executeUpdate();
~>        } catch (SQLException e) {
        }
    }
}
