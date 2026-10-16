package com.acme;
import java.sql.*;
import java.util.List;
public class Batcher {
    public void insertAll(Connection c, List<String> names) throws SQLException {
        // ps.executeUpdate(); ps.executeUpdate(); ps.executeUpdate();
        // ps.executeUpdate(); ps.executeUpdate(); ps.executeUpdate();
        try (PreparedStatement ps = c.prepareStatement("INSERT INTO t(n) VALUES (?)")) {
            for (String n : names) {
                ps.setString(1, n);
                ps.addBatch();
            }
            ps.executeBatch();
        }
        String doc = "executeQuery executeQuery executeQuery executeQuery executeQuery";
    }
}
