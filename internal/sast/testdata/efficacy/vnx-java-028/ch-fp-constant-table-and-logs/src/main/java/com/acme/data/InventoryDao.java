package com.acme.data;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import org.slf4j.Logger;
import @@sample:o[r]g[.][s]lf[4]j[.][L]og[g]er[F]ac[t]or[y]@@;

public class InventoryDao {
    private static final Logger log = LoggerFactory.getLogger(InventoryDao.class);
    private static final String TABLE_NAME = "inventory";
    private static final String BY_SKU = "SELECT qty FROM " + TABLE_NAME + " WHERE sku = ?";
    private final Connection conn;

    public InventoryDao(Connection conn) {
        this.conn = conn;
    }

    public int qty(String sku) throws SQLException {
        log.debug("Executing select for sku " + sku);
        try (PreparedStatement ps = conn.prepareStatement(BY_SKU)) {
            ps.setString(1, sku);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getInt(1) : 0;
            }
        }
    }

    public void reset() throws SQLException {
        conn.createStatement().executeUpdate("UPDATE " + TABLE_NAME + " SET qty = 0 WHERE qty < 0");
    }
}
