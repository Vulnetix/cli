package com.acme.db;

import java.sql.Connection;
import java.sql.SQLException;

public class AuditWriter {
    private final Connection conn;

    public AuditWriter(Connection conn) {
        this.conn = conn;
    }

    public void close() {
        try {
            conn.close();
~>        } catch (SQLException e) {

        }
    }

    public void record(String event) throws InterruptedException {
        try {
            Thread.sleep(10);
        }
~>        catch (InterruptedException e)
        {
        }
    }
}
