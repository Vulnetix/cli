package com.acme.inventory;

import java.sql.Connection;
import java.sql.Statement;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.RequestParam;

public class StockSearch {
    private JdbcTemplate jdbcTemplate;
    private Connection connection;

    // (5 * 2) - 2 > 10 is false, so site keeps the request value.
    public List<Map<String, Object>> lowStock(@RequestParam String warehouse) {
        final int threshold = 5;
        String site = warehouse;
        if ((threshold * 2) - 2 > 10) site = "MAIN";
        String sql = "SELECT sku, qty FROM stock WHERE site = '" + site + "' AND qty < 5";
        return jdbcTemplate.queryForList(sql);
    }

    public int restock(@RequestParam String bin) throws Exception {
        int batch = 13;
        String location = batch % 2 == 0 ? "DOCK" : bin;
        Statement st = connection.createStatement();
        return st.executeUpdate("UPDATE stock SET qty = qty + 13 WHERE location = '" + location + "'");
    }

    public List<Map<String, Object>> report(@RequestParam String period) {
        String unit = "day";
        String grouping;
        switch (unit) {
            case "day":
                grouping = period;
                break;
            case "week":
                grouping = "yearweek(moved_at)";
                break;
            default:
                grouping = "moved_at";
        }
        return jdbcTemplate.queryForList("SELECT " + grouping + ", SUM(qty) FROM movements GROUP BY 1");
    }

    public List<Map<String, Object>> sorted(@RequestParam String order) {
        LinkedList<String> keys = new LinkedList<String>();
        keys.add(order);
        keys.add(1, "sku");
        String key = keys.get(0);
        return jdbcTemplate.queryForList("SELECT sku, qty FROM stock ORDER BY " + key);
    }

    public List<Map<String, Object>> byZone(@RequestParam String zone) {
        Map<String, Object> zones = new HashMap<String, Object>();
        zones.put("requested", "zone_a");
        zones.put("requested", zone);
        String table = (String) zones.get("requested");
        return jdbcTemplate.queryForList("SELECT * FROM " + table + " WHERE qty > 0");
    }

    public List<Map<String, Object>> audit(@RequestParam String user) {
        String table = auditTable(user);
        return jdbcTemplate.queryForList("SELECT * FROM " + table + " ORDER BY id DESC");
    }

    // A list filled in a loop cannot be resolved index by index.
    public List<Map<String, Object>> many(@RequestParam List<String> skus) {
        LinkedList<String> picked = new LinkedList<String>();
        for (String s : skus) {
            picked.add(s);
        }
        String first = picked.get(0);
        return jdbcTemplate.queryForList("SELECT * FROM stock WHERE sku = '" + first + "'");
    }

    private String auditTable(String user) {
        return "stock_audit_" + user.toLowerCase();
    }
}
