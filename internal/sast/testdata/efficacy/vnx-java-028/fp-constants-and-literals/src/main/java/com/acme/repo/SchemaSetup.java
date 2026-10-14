package com.acme.repo;

import java.sql.Connection;
import java.sql.Statement;

public class SchemaSetup {
    private static final String TABLE = "audit_log";
    private static final String COLUMNS = "id BIGINT, msg VARCHAR(255)";

    public void create(Connection c) throws Exception {
        Statement st = c.createStatement();
        st.execute("CREATE TABLE IF NOT EXISTS " + TABLE + " (" + COLUMNS + ")");
        st.executeUpdate("DELETE FROM " + TABLE + " WHERE created < now() - interval '30 days'");
        st.executeQuery("SELECT phone FROM employees;");
        String sql = "SELECT * FROM " + "users " + "WHERE active = true";
        st.executeQuery(sql);
        // st.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
        String help = "never call stmt.executeQuery(\"SELECT ... '\" + name + \"'\")";
        System.out.println(help);
    }
}
