package com.acme;

import java.sql.*;

public class ReportService {
    private final DataSource ds;

    public ReportService(DataSource ds) {
        this.ds = ds;
    }

~>    public Report build(long accountId) throws SQLException {
        try (Connection c = ds.getConnection()) {
            Report r = new Report();
            PreparedStatement ps1 = c.prepareStatement("SELECT name FROM account WHERE id = ?");
            ps1.setLong(1, accountId);
            ResultSet a = ps1.executeQuery();
            PreparedStatement ps2 = c.prepareStatement("SELECT count(*) FROM orders WHERE account_id = ?");
            ps2.setLong(1, accountId);
            ResultSet o = ps2.executeQuery();
            PreparedStatement ps3 = c.prepareStatement("SELECT sum(total) FROM invoice WHERE account_id = ?");
            ps3.setLong(1, accountId);
            ResultSet inv = ps3.executeQuery();
            Statement st = c.createStatement();
            st.execute("REFRESH MATERIALIZED VIEW account_stats");
            PreparedStatement ps4 = c.prepareStatement("UPDATE account SET last_report = now() WHERE id = ?");
            ps4.setLong(1, accountId);
            ps4.executeUpdate();
            return r;
        }
    }
}
