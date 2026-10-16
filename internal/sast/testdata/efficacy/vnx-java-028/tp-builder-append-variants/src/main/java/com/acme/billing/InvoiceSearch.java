package com.acme.billing;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;

public class InvoiceSearch {
    private final JdbcTemplate jdbcTemplate;
    private final Connection conn;

    public InvoiceSearch(JdbcTemplate jdbcTemplate, Connection conn) {
        this.jdbcTemplate = jdbcTemplate;
        this.conn = conn;
    }

    public List<Map<String, Object>> byCustomer(String customer, String status) {
        StringBuilder q = new StringBuilder();
        q.append("SELECT id, total FROM invoices WHERE customer = '");
        q.append(customer);
        q.append("'");
        if (status != null) {
            q.append(" AND status = '" + status + "'");
        }
~>        return jdbcTemplate.queryForList(q.toString());
    }

    public ResultSet overdue(String region) throws Exception {
        StringBuffer buf = new StringBuffer("SELECT * FROM invoices WHERE due < now()");
        buf.append(" AND region = ")
            .append(quote(region));
        Statement stmt = conn.createStatement();
~>        return stmt.executeQuery(buf.toString());
    }

    public int close(String number) throws Exception {
        Statement stmt = conn.createStatement();
~>        return stmt.executeUpdate(new StringBuilder("UPDATE invoices SET closed = 1 WHERE number = ").append(number).toString());
    }

    private String quote(String s) {
        return "'" + s + "'";
    }
}
