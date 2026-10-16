package com.acme.repo;

import java.sql.*;

public class UserRepo {
    ResultSet find(Connection conn, String name, String city) throws SQLException {
        StringBuilder sb = new StringBuilder("SELECT * FROM users WHERE 1=1");
        sb.append(" AND name = '").append(name).append("'");
        if (city != null) {
            sb.append(" AND city = '" + city + "'");
        }
        Statement st = conn.createStatement();
~>        return st.executeQuery(sb.toString());
    }
}
