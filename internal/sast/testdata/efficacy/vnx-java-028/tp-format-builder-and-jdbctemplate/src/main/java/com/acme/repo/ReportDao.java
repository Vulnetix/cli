package com.acme.repo;

import java.sql.Connection;
import java.sql.Statement;
import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;

public class ReportDao {
    private final JdbcTemplate jdbcTemplate;

    public ReportDao(JdbcTemplate jdbcTemplate) { this.jdbcTemplate = jdbcTemplate; }

    public void purge(Connection c, String userId) throws Exception {
        String sql = String.format("DELETE FROM sessions WHERE user_id = '%s'", userId);
        Statement st = c.createStatement();
        st.executeUpdate(sql);
        st.execute(String.format("DROP TABLE tmp_%s", userId));
    }

    public List<Map<String, Object>> byRegion(String region) {
        return jdbcTemplate.queryForList("SELECT * FROM sales WHERE region = '" + region + "'");
    }

    public int bump(String sku) {
        StringBuilder sb = new StringBuilder("UPDATE stock SET qty = qty + 1 WHERE sku = '");
        sb.append(sku).append("'");
~>        return jdbcTemplate.update(sb.toString());
    }

    public Long total(String table) {
        String q = "SELECT COUNT(*) FROM ".concat(table);
        return jdbcTemplate.queryForObject(q, Long.class);
    }
}
