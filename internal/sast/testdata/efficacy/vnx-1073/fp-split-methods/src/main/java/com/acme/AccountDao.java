package com.acme;

import java.sql.*;

public class AccountDao {
    private final Connection c;

    public AccountDao(Connection c) {
        this.c = c;
    }

    public ResultSet byId(long id) throws SQLException {
        PreparedStatement ps = c.prepareStatement("SELECT * FROM account WHERE id = ?");
        ps.setLong(1, id);
        return ps.executeQuery();
    }

    public int rename(long id, String name) throws SQLException {
        PreparedStatement ps = c.prepareStatement("UPDATE account SET name = ? WHERE id = ?");
        ps.setString(1, name);
        ps.setLong(2, id);
        return ps.executeUpdate();
    }

    public int close(long id) throws SQLException {
        PreparedStatement ps = c.prepareStatement("UPDATE account SET closed = true WHERE id = ?");
        ps.setLong(1, id);
        int n = ps.executeUpdate();
        PreparedStatement audit = c.prepareStatement("INSERT INTO audit(account_id) VALUES (?)");
        audit.setLong(1, id);
        audit.executeUpdate();
        return n;
    }

    private int purge() throws SQLException {
        Statement st = c.createStatement();
        return st.executeUpdate("DELETE FROM account WHERE closed");
    }
}
