package com.acme.imp;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.List;

public class Importer {
    public void importAll(Connection c, List<Row> rows) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement("insert into t values (?, ?)")) {
            for (Row r : rows) {
                ps.setLong(1, r.id());
                ps.setString(2, r.name());
                ps.addBatch();
            }
            ps.executeBatch();
        }
    }
}
