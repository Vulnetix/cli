package com.acme.repo;

import java.sql.*;

public class Labels {
    String banner(String user) {
        StringBuilder msg = new StringBuilder("Hello, ");
        msg.append(user).append("! Welcome back.");
        return msg.toString();
    }

    void log(Statement st, String user) throws SQLException {
        StringBuilder b = new StringBuilder();
        b.append(user);
        System.out.println(b.toString());
        st.executeQuery("SELECT 1");
    }
}
