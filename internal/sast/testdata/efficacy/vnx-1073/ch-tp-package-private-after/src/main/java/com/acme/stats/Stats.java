package com.acme.stats;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class Stats {
    private final Connection conn;

    public Stats(Connection conn) {
        this.conn = conn;
    }

    public int users() throws SQLException {
        try (Statement st = conn.createStatement()) {
            ResultSet rs = st.executeQuery("select count(*) from users");
            rs.next();
            return rs.getInt(1);
        }
    }

~>    void refresh() throws SQLException {
        try (Statement st = conn.createStatement()) {
            st.executeUpdate("delete from daily");
            st.executeUpdate("insert into daily select * from raw");
            st.executeQuery("select 1");
            st.executeUpdate("update meta set refreshed = now()");
            st.executeUpdate("vacuum daily");
        }
    }
}
