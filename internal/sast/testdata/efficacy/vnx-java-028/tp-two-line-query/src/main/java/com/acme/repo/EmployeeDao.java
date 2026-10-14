package com.acme.repo;

import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

public class EmployeeDao {
    public ResultSet find(Connection connection, String lastName, String tan) throws Exception {
        String query =
            "SELECT * FROM employees WHERE last_name = '"
                + lastName
                + "' AND auth_tan = '"
                + tan
                + "'";
        Statement statement = connection.createStatement();
~>        return statement.executeQuery(query);
    }

    public void log(Connection connection, String action) throws Exception {
        String logQuery = "INSERT INTO access_log (action) VALUES ('" + action + "')";
        Statement statement = connection.createStatement();
~>        statement.executeUpdate(logQuery);
~>        statement.addBatch(logQuery);
    }

    public ResultSet call(Connection connection, String proc) throws Exception {
        String sql = "{call " + proc + "}";
~>        CallableStatement cs = connection.prepareCall(sql);
        return cs.executeQuery();
    }

    public ResultSet search(Connection connection, String user) throws Exception {
        String sql = "SELECT * FROM users WHERE USERNAME=? AND PASSWORD='" + user + "'";
~>        PreparedStatement ps = connection.prepareStatement(sql);
        ps.setString(1, "foo");
        return ps.executeQuery();
    }

    public ResultSet filter(Connection connection, String status, String order) throws Exception {
        String sql = "SELECT * FROM orders WHERE 1=1";
        sql += " AND status = '" + status + "'";
        Statement statement = connection.createStatement();
~>        return statement.executeQuery(sql);
    }
}
