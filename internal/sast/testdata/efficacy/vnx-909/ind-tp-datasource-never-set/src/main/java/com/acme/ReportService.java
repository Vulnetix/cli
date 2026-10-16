package com.acme;

import java.sql.Connection;
import java.sql.SQLException;
import javax.sql.DataSource;

public class ReportService {
~>    private DataSource dataSource;

    public int count() throws SQLException {
        try (Connection c = dataSource.getConnection()) {
            return c.createStatement().executeQuery("select 1").getInt(1);
        }
    }
}
