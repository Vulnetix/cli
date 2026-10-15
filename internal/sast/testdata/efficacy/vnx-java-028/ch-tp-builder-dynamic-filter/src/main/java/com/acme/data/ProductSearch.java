package com.acme.data;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;

public class ProductSearch {
    private final Connection conn;

    public ProductSearch(Connection conn) {
        this.conn = conn;
    }

    public ResultSet search(String category, String sort) throws SQLException {
        StringBuilder sb = new StringBuilder("SELECT * FROM products WHERE 1=1");
        if (category != null) {
            sb.append(" AND category = '").append(category).append("'");
        }
        sb.append(" ORDER BY ").append(sort);
~>        return conn.createStatement().executeQuery(sb.toString());
    }
}
