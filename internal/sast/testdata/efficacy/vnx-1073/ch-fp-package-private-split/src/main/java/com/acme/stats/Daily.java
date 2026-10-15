package com.acme.stats;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

public class Daily {
    private final Connection conn;

    public Daily(Connection conn) {
        this.conn = conn;
    }

    public void clear() throws SQLException {
        try (Statement st = conn.createStatement()) {
            st.executeUpdate("delete from daily");
            st.executeUpdate("delete from weekly");
        }
    }

    void load() throws SQLException {
        try (Statement st = conn.createStatement()) {
            st.executeUpdate("insert into daily select * from raw");
            st.executeUpdate("insert into weekly select * from raw");
        }
    }

    int count() throws SQLException {
        try (Statement st = conn.createStatement()) {
            return st.executeQuery("select count(*) from daily").getInt(1);
        }
    }
}
