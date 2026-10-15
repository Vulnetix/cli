package com.acme.audit;

import java.sql.Connection;
import java.sql.PreparedStatement;

public class AuditDao {
    private static final String TABLE_NAME = "audit_log";
    private static final String COLUMNS = "id, actor, action";
    private Connection conn;

    public void load(long id) throws Exception {
        PreparedStatement ps = conn.prepareStatement("SELECT " + COLUMNS + " FROM " + TABLE_NAME + " WHERE id = ?");
        ps.setLong(1, id);
        conn.createStatement().executeUpdate("DELETE FROM " + TABLE_NAME + " WHERE created < now() - interval '90 days'");
    }
}
