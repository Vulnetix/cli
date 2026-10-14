package com.acme.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import org.springframework.jdbc.core.JdbcTemplate;

public class AccountDao {
    private JdbcTemplate jdbcTemplate;

    public ResultSet find(Connection connection, String name) throws Exception {
        PreparedStatement ps = connection.prepareStatement("SELECT * FROM accounts WHERE name = ?");
        ps.setString(1, name);
        jdbcTemplate.update("UPDATE accounts SET seen = 1 WHERE name = ?", name);
        jdbcTemplate.queryForList("SELECT * FROM accounts WHERE owner = ? AND tier = ?", name, "gold" + name);
        return ps.executeQuery();
    }
}
