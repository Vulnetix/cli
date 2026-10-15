package com.acme.data;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class ReportDao {
    private final Connection conn;

    public ReportDao(Connection conn) {
        this.conn = conn;
    }

    public PreparedStatement monthly(int year, String region) throws SQLException {
        String sql = "SELECT region, SUM(total) "
                + "FROM sales "
                + "WHERE year = ? AND region = ? "
                + "GROUP BY region";
        PreparedStatement ps = conn.prepareStatement(sql);
        ps.setInt(1, year);
        ps.setString(2, region);
        return ps;
    }

    public void run(java.util.concurrent.ExecutorService pool, String job) {
        pool.execute(() -> System.out.println("select job " + job));
    }
}
