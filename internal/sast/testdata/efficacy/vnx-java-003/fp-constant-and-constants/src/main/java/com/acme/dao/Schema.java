package com.acme.dao;

import java.sql.Connection;
import java.sql.Statement;

public class Schema {
    private static final String TABLE = "accounts";
    private static final String COLUMNS = "id, name";

    public void init(Connection connection) throws Exception {
        Statement statement = connection.createStatement();
        statement.execute("CREATE TABLE IF NOT EXISTS accounts (id INT, name VARCHAR(64))");
        statement.executeQuery("SELECT " + COLUMNS + " FROM " + TABLE);
        String sql = "SELECT max(id) FROM accounts";
        statement.executeQuery(sql);
        statement.executeUpdate("DELETE FROM accounts " + "WHERE id < 0");
    }
}
