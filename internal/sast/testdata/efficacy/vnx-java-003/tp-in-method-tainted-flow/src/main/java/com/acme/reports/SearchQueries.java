package com.acme.reports;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;

public class SearchQueries {
    private Connection connection;

    // 10 * 2 > 60 is false: the request value is the one that is used.
    public ResultSet byRegion(HttpServletRequest request) throws Exception {
        String region = request.getParameter("region");
        int pageSize = 10;
        String column;
        if (pageSize * 2 > 60) column = "region_code";
        else column = region;
        String sql = "SELECT id, total FROM orders ORDER BY " + column;
        Statement st = connection.createStatement();
~>        return st.executeQuery(sql);
    }

    public ResultSet byStatus(HttpServletRequest request) throws Exception {
        String status = request.getParameter("status");
        int version = 2;
        String filter = version > 3 ? "'OPEN'" : status;
        Statement st = connection.createStatement();
~>        return st.executeQuery("SELECT id FROM tickets WHERE status = " + filter);
    }

    // The switch selects the case that keeps the request value.
    public ResultSet byKind(HttpServletRequest request) throws Exception {
        String kind = request.getParameter("kind");
        String mode = "detail";
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
                view = "orders";
                break;
        }
        Statement st = connection.createStatement();
~>        return st.executeQuery("SELECT * FROM " + view);
    }

    // After remove(0), index 0 holds the request value.
    public ResultSet byColumns(HttpServletRequest request) throws Exception {
        String requested = request.getParameter("col");
        List<String> columns = new ArrayList<>();
        columns.add("id");
        columns.add(requested);
        columns.add("created_at");
        columns.remove(0);
        String sortBy = columns.get(0);
        Statement st = connection.createStatement();
~>        return st.executeQuery("SELECT id FROM users ORDER BY " + sortBy);
    }

    public ResultSet byTenant(HttpServletRequest request) throws Exception {
        Map<String, String> names = new HashMap<>();
        names.put("user", request.getParameter("tenant"));
        names.put("system", "tenant_default");
        String schema = names.get("user");
        Statement st = connection.createStatement();
~>        return st.executeQuery("SELECT * FROM " + schema + ".settings");
    }

    // A same-file helper that returns (a transform of) its parameter.
    public ResultSet archived(HttpServletRequest request) throws Exception {
        String year = request.getParameter("year");
        String table = archiveTable(year);
        Statement st = connection.createStatement();
~>        return st.executeQuery("SELECT COUNT(*) FROM " + table);
    }

    // Not resolvable in this method: a condition on request data, and a call
    // into another class. Both stay reported.
    public ResultSet fallback(HttpServletRequest request) throws Exception {
        String region = request.getParameter("region");
        String column = "region_code";
        if (request.getParameter("raw") != null) {
            column = region;
        }
        String table = TableNames.forRegion(region);
        Statement st = connection.createStatement();
~>        st.executeQuery("SELECT id FROM orders ORDER BY " + column);
~>        return st.executeQuery("SELECT id FROM " + table);
    }

    private static String archiveTable(String year) {
        if (year == null) {
            return "orders";
        }
        return "orders_" + year.trim();
    }
}
