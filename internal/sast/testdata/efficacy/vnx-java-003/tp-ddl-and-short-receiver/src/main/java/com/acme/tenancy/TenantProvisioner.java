package com.acme.tenancy;

import java.sql.Connection;
import java.sql.Statement;
import org.springframework.jdbc.core.JdbcTemplate;

public class TenantProvisioner {
    private final JdbcTemplate jdbcTemplate;
    private final Connection connection;

    public TenantProvisioner(JdbcTemplate jdbcTemplate, Connection connection) {
        this.jdbcTemplate = jdbcTemplate;
        this.connection = connection;
    }

    public void provision(Tenant tenant) {
~>        jdbcTemplate.execute("CREATE SCHEMA \"" + tenant.getSlug() + "\" AUTHORIZATION dba");
    }

    public void retire(String slug) throws Exception {
        Statement st = connection.createStatement();
~>        st.execute(String.format("DROP SCHEMA %s CASCADE", slug));
    }

    public void rename(String slug, String next) throws Exception {
        String ddl = "ALTER SCHEMA " + slug
                + " RENAME TO " + next;
        Statement st = connection.createStatement();
~>        st.execute(ddl);
    }

    public void reset() throws Exception {
        Statement st = connection.createStatement();
        st.execute("TRUNCATE TABLE " + Tenants.AUDIT_TABLE);
    }
}
