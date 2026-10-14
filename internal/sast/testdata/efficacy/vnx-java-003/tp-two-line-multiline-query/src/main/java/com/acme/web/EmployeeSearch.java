package com.acme.web;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class EmployeeSearch {
    public ResultSet search(HttpServletRequest req, Connection connection) throws Exception {
        String lastName = req.getParameter("last");
        String tan = req.getParameter("tan");
        String query =
            "SELECT * FROM employees WHERE last_name = '"
                + lastName
                + "' AND auth_tan = '"
                + tan
                + "'";
        Statement statement = connection.createStatement();
~>        ResultSet results = statement.executeQuery(query);

        String sql = "SELECT * FROM audit WHERE 1=1";
        sql += " AND actor = '" + lastName + "'";
~>        statement.addBatch(sql);
        return results;
    }
}
