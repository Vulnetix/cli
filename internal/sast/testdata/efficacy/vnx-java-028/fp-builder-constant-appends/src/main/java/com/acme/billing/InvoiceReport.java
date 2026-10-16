package com.acme.billing;

import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;

public class InvoiceReport {
    private static final String TABLE = "invoices";
    private static final String ORDER = " ORDER BY due";
    private final JdbcTemplate jdbcTemplate;

    public InvoiceReport(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public List<Map<String, Object>> open(String customer, boolean recentFirst) {
        StringBuilder sql = new StringBuilder("SELECT id, total FROM ");
        sql.append(TABLE).append(" WHERE customer = ? AND closed = 0");
        if (recentFirst) {
            sql.append(ORDER).append(" DESC");
        }
        return jdbcTemplate.queryForList(sql.toString(), customer);
    }

    public List<Map<String, Object>> sorted(String requested) {
        int pageSize = 50;
        String column;
        if (pageSize * 2 > 60) column = "due";
        else column = requested;
        StringBuilder sb = new StringBuilder("SELECT id FROM invoices ORDER BY ");
        sb.append(column);
        return jdbcTemplate.queryForList(sb.toString());
    }

    public String describe(String customer) {
        StringBuilder msg = new StringBuilder("report for ");
        msg.append(customer);
        jdbcTemplate.execute("ANALYZE invoices");
        return msg.toString();
    }
}
