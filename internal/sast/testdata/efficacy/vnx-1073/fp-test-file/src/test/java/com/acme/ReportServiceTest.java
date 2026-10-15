package com.acme;

import java.sql.*;
import org.junit.jupiter.api.Test;

class ReportServiceTest {
    @Test
    public void seedsAndReads() throws Exception {
        Connection c = TestDb.open();
        Statement st = c.createStatement();
        st.executeUpdate("INSERT INTO account VALUES (1, 'a')");
        st.executeUpdate("INSERT INTO orders VALUES (1, 1)");
        st.executeUpdate("INSERT INTO invoice VALUES (1, 1, 10)");
        st.executeUpdate("INSERT INTO invoice VALUES (2, 1, 20)");
        ResultSet rs = st.executeQuery("SELECT * FROM account_stats");
    }
}
