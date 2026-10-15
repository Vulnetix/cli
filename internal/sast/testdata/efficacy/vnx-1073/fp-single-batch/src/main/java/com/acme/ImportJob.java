package com.acme;

import java.sql.*;
import java.util.List;

public class ImportJob {
    public int[] load(Connection c, List<Row> rows) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement("INSERT INTO item(id, name) VALUES (?, ?)")) {
            for (Row row : rows) {
                ps.setLong(1, row.id());
                ps.setString(2, row.name());
                ps.addBatch();
            }
            return ps.executeBatch();
        }
    }
}
