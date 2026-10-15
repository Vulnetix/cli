package com.acme.report;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class InventoryDao {
    private static final String QUERY =
~>        "SELECT i.sku, w.name, s.name, c.label, b.code, z.zone " +
        "FROM items i " +
        "JOIN warehouses w ON w.id = i.warehouse_id " +
        "JOIN suppliers s ON s.id = i.supplier_id " +
        "LEFT JOIN categories c ON c.id = i.category_id " +
        "JOIN bins b ON b.id = i.bin_id " +
        "JOIN zones z ON z.id = b.zone_id " +
        "WHERE i.active = 1";

    public PreparedStatement prepare(Connection conn) throws SQLException {
        return conn.prepareStatement(QUERY);
    }
}
