package com.acme.dao;

import java.sql.*;

public class Consts {
    private static final String TABLE = "orders";

    public ResultSet all(Statement stmt, boolean onlyActive) throws SQLException {
        String sql = "SELECT id, total FROM " + TABLE;
        sql += " WHERE total > 0";
        sql = sql + " ORDER BY id";
        // stmt.executeQuery("SELECT * FROM x WHERE a = " + onlyActive);
        return stmt.executeQuery(sql);
    }
}
