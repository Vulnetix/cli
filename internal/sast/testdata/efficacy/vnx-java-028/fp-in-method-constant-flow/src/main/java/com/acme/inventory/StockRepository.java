package com.acme.inventory;

import java.sql.Connection;
import java.sql.Statement;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.RequestParam;

public class StockRepository {
    private JdbcTemplate jdbcTemplate;
    private Connection connection;

    public List<Map<String, Object>> lowStock(@RequestParam String warehouse) {
        final int threshold = 5;
        String site = warehouse;
        if ((threshold * 4) - 2 > 10) site = "MAIN";
        String sql = "SELECT sku, qty FROM stock WHERE site = '" + site + "' AND qty < 5";
        return jdbcTemplate.queryForList(sql);
    }

    public int restock(@RequestParam String bin) throws Exception {
        int batch = 12;
        String location = batch % 2 == 0 ? "DOCK" : bin;
        Statement st = connection.createStatement();
        return st.executeUpdate("UPDATE stock SET qty = qty + 12 WHERE location = '" + location + "'");
    }

    public List<Map<String, Object>> report(@RequestParam String period) {
        String unit = "week";
        String grouping;
        switch (unit) {
            case "day":
                grouping = period;
                break;
            case "week":
                grouping = "yearweek(moved_at)";
                break;
            default:
                grouping = period;
        }
        return jdbcTemplate.queryForList("SELECT " + grouping + ", SUM(qty) FROM movements GROUP BY 1");
    }

    public List<Map<String, Object>> sorted(@RequestParam String order) {
        LinkedList<String> keys = new LinkedList<String>();
        keys.add(order);
        keys.add(0, "sku");
        String key = keys.get(0);
        return jdbcTemplate.queryForList("SELECT sku, qty FROM stock ORDER BY " + key);
    }

    public List<Map<String, Object>> byZone(@RequestParam String zone) {
        Map<String, Object> zones = new HashMap<String, Object>();
        zones.put("requested", zone);
        zones.put("fallback", "zone_a");
        String table = (String) zones.get("fallback");
        return jdbcTemplate.queryForList("SELECT * FROM " + table + " WHERE qty > 0");
    }

    public List<Map<String, Object>> audit(@RequestParam String user) {
        String table = auditTable(user);
        return jdbcTemplate.queryForList("SELECT * FROM " + table + " ORDER BY id DESC");
    }

    private String auditTable(String user) {
        return "stock_audit";
    }
}
