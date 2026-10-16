package com.acme.ledger;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import javax.sql.DataSource;

public class AccountDao {
    private final DataSource dataSource;

    public AccountDao(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    public void credit(long id, long amount) throws SQLException {
~>        Connection conn = dataSource.getConnection();
~>        PreparedStatement ps = conn.prepareStatement("UPDATE accounts SET balance = balance + ? WHERE id = ?");
        ps.setLong(1, amount);
        ps.setLong(2, id);
        ps.executeUpdate();
        ps.close();
        conn.close();
    }
}
