package com.acme.catalog;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import javax.sql.DataSource;

public class ProductRepository {
    private final DataSource ds;

    public ProductRepository(DataSource ds) {
        this.ds = ds;
    }

    public Product findBySku(String sku) {
        try (Connection c = ds.getConnection();
             PreparedStatement ps = c.prepareStatement("SELECT id, name FROM product WHERE sku = ?")) {
            ps.setString(1, sku);
            ResultSet rs = ps.executeQuery();
            return rs.next() ? new Product(rs.getLong(1), rs.getString(2)) : null;
~>        } catch (Exception e) {
            return null;
        }
    }
}
