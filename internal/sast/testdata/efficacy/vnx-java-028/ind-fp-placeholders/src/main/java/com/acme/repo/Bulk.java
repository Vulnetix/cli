package com.acme.repo;

import java.sql.*;
import java.util.List;

public class Bulk {
    PreparedStatement build(Connection c, List<Long> ids) throws SQLException {
        StringBuilder sql = new StringBuilder("SELECT * FROM items WHERE id IN (");
        for (int i = 0; i < ids.size(); i++) {
            sql.append(i == 0 ? "?" : ",?");
        }
        sql.append(")");
        PreparedStatement ps = c.prepareStatement(sql.toString());
        for (int i = 0; i < ids.size(); i++) ps.setLong(i + 1, ids.get(i));
        return ps;
    }
}
