package com.acme.dao;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class QueryRunner {
    // Runs SQL its callers composed; whether it is safe is decided there.
    public ResultSet run(Connection connection, String sql) throws Exception {
        Statement statement = connection.createStatement();
        return statement.executeQuery(sql);
    }
}
