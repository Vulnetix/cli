package com.acme;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class SqlDao {
    public ResultSet find(Connection c, String name) throws Exception {
        Statement st = c.createStatement();
        return st.executeQuery("select * from users where name = '" + name + "'");
    }
}
