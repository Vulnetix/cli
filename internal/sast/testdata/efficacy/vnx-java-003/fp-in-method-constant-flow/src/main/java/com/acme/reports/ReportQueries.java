package com.acme.reports;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;

public class ReportQueries {
    private Connection connection;

    // The request value is only kept on a branch the constant condition
    // never takes: 50 * 2 > 60.
    public ResultSet byRegion(HttpServletRequest request) throws Exception {
        String region = request.getParameter("region");
        int pageSize = 50;
        String column;
        if (pageSize * 2 > 60) column = "region_code";
        else column = region;
        String sql = "SELECT id, total FROM orders ORDER BY " + column;
        Statement st = connection.createStatement();
        return st.executeQuery(sql);
    }

    public ResultSet byStatus(HttpServletRequest request) throws Exception {
        String status = request.getParameter("status");
        int version = 2;
        String filter = version > 1 ? "'OPEN'" : status;
        Statement st = connection.createStatement();
        return st.executeQuery("SELECT id FROM tickets WHERE status = " + filter);
    }

    public int purge(HttpServletRequest request) throws Exception {
        String table = request.getParameter("table");
        final int retentionDays = 30;
        String target = table;
        if (retentionDays >= 7) {
            target = "audit_log";
        } else {
            target = table;
        }
        Statement st = connection.createStatement();
        return st.executeUpdate("DELETE FROM " + target + " WHERE age_days > 30");
    }

    // A switch on a value fixed in the method: mode.charAt(0) is 's'.
    public ResultSet byKind(HttpServletRequest request) throws Exception {
        String kind = request.getParameter("kind");
        String mode = "summary";
        char first = mode.charAt(0);
        String view;
        switch (first) {
            case 'd':
                view = kind;
                break;
            case 's':
                view = "order_summary";
                break;
            default:
                view = kind;
                break;
        }
        Statement st = connection.createStatement();
        return st.executeQuery("SELECT * FROM " + view);
    }

    // A list used to carry values: after remove(1), index 1 is "created_at".
    public ResultSet byColumns(HttpServletRequest request) throws Exception {
        String requested = request.getParameter("col");
        List<String> columns = new ArrayList<>();
        columns.add("id");
        columns.add(requested);
        columns.add("created_at");
        columns.remove(1);
        String sortBy = columns.get(1);
        Statement st = connection.createStatement();
        return st.executeQuery("SELECT id FROM users ORDER BY " + sortBy);
    }

    // A map read back under a key that only ever held a literal.
    public ResultSet byTenant(HttpServletRequest request) throws Exception {
        Map<String, String> names = new HashMap<>();
        names.put("user", request.getParameter("tenant"));
        names.put("system", "tenant_default");
        String schema = names.get("system");
        Statement st = connection.createStatement();
        return st.executeQuery("SELECT * FROM " + schema + ".settings");
    }

    // Helpers in this file whose every return is a constant.
    public ResultSet archived(HttpServletRequest request) throws Exception {
        String year = request.getParameter("year");
        String table = archiveTable(year);
        Statement st = connection.createStatement();
        return st.executeQuery("SELECT COUNT(*) FROM " + table);
    }

    public ResultSet legacy(HttpServletRequest request) throws Exception {
        String hint = request.getParameter("hint");
        String table = new Naming().pick(hint);
        Statement st = connection.createStatement();
        return st.executeQuery("SELECT * FROM " + table + " WHERE active = 1");
    }

    private static String archiveTable(String year) {
        String name = "orders_archive";
        if (year == null) {
            return "orders";
        }
        return name;
    }

    private static class Naming {
        String pick(String hint) {
            String base = "legacy";
            return base + "_orders";
        }
    }
}
