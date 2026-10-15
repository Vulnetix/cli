package com.acme.repo;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import org.springframework.jdbc.core.JdbcTemplate;

public class UserRepo {
    private final JdbcTemplate jdbcTemplate;
    private javax.sql.DataSource dataSource;

    public UserRepo(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public int disable(long id) throws SQLException {
~>        Connection conn = jdbcTemplate.getDataSource().getConnection();
        PreparedStatement ps = conn.prepareStatement("UPDATE users SET active = false WHERE id = ?");
        ps.setLong(1, id);
        return ps.executeUpdate();
    }

    public boolean ping() throws SQLException {
~>        Connection c = this.dataSource.getConnection();
        return c.isValid(1);
    }
}
