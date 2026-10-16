package com.acme;
import java.sql.*;
public class Report {
~>    public void rebuild(Connection c) throws SQLException {
        try (Statement st = c.createStatement()) {
            st.executeUpdate("DELETE FROM summary");
            st.executeUpdate("INSERT INTO summary SELECT region, sum(x) FROM sales GROUP BY region");
            ResultSet a = st.executeQuery("SELECT count(*) FROM summary");
            ResultSet b = st.executeQuery("SELECT max(x) FROM summary");
            st.executeUpdate("UPDATE meta SET refreshed = now()");
        }
    }
}
