package com.acme.data;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

public class SessionStore {
    private final Connection conn;

    public SessionStore(Connection conn) {
        this.conn = conn;
    }

    public void revoke(String token) throws SQLException {
        String sql = String.format("DELETE FROM sessions WHERE token = '%s'", token);
        try (Statement stmt = conn.createStatement()) {
            stmt.executeUpdate(sql);
        }
    }

    public void touch(String user) throws SQLException {
        String query = "UPDATE sessions SET last_seen = now() WHERE username = '"
                + user + "'";
        Statement st = conn.createStatement();
        st.execute(query);
    }
}
