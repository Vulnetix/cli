package com.acme;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import javax.sql.DataSource;

public class ReportExporter {
    private final DataSource ds;

    public ReportExporter(DataSource ds) {
        this.ds = ds;
    }

    public void export(String path) throws Exception {
        try (Connection conn = ds.getConnection();
             PreparedStatement ps = conn.prepareStatement("SELECT id, total FROM orders");
             ResultSet rs = ps.executeQuery();
             BufferedWriter out = new BufferedWriter(
                     new OutputStreamWriter(new FileOutputStream(path), StandardCharsets.UTF_8))) {
            while (rs.next()) {
                out.write(rs.getLong(1) + "," + rs.getBigDecimal(2));
                out.newLine();
            }
        }
    }
}
