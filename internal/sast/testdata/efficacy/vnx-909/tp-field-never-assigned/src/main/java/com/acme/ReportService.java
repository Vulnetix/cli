package com.acme;

import java.sql.Connection;
import java.sql.SQLException;
import javax.crypto.Cipher;
import javax.sql.DataSource;

public class ReportService {
~>    private DataSource dataSource;
~>    private Cipher cipher;
    private final String table = "reports";

    public int count() throws SQLException {
        try (Connection c = dataSource.getConnection()) {
            return c.createStatement().executeQuery("select count(*) from " + table).getInt(1);
        }
    }

    public byte[] seal(byte[] data) throws Exception {
        return this.cipher.doFinal(data);
    }
}
