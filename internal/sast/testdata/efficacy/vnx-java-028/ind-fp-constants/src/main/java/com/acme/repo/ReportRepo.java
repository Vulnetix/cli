package com.acme.repo;

import java.sql.*;

public class ReportRepo {
    private static final String TABLE = "reports";

    ResultSet run(Connection conn, long id) throws SQLException {
        StringBuilder sql = new StringBuilder("SELECT id, title FROM ");
        sql.append(TABLE).append(" WHERE owner = ?");
        PreparedStatement ps = conn.prepareStatement(sql.toString());
        ps.setLong(1, id);
        return ps.executeQuery();
    }
}
