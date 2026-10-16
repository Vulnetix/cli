package com.acme.repo;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class UserRepository {
    private final Connection conn;

    public UserRepository(Connection conn) { this.conn = conn; }

    public ResultSet byName(String name) throws SQLException {
        Statement stmt = conn.createStatement();
        return stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    }

    public void rename(long id, String newName) throws SQLException {
        Statement stmt = conn.createStatement();
        stmt.executeUpdate("UPDATE users SET name='"+newName+"' WHERE id=" + id);
        stmt.execute("SET SCHEMA \"" + newName + "\"");
    }

    public ResultSet byKid(String kid) throws SQLException {
        ResultSet rs =
            conn
                .createStatement()
                .executeQuery(
                    "SELECT key FROM jwt_keys WHERE id = '" + kid + "'");
        return rs;
    }
}
