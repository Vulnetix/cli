package io.acme;

import com.zaxxer.hikari.HikariDataSource;

public class DataSourceConfig {
    public HikariDataSource dataSource() {
        HikariDataSource ds = new HikariDataSource();
        ds.setJdbcUrl("jdbc:postgresql://db:5432/app");
        ds.setUsername("app");
~>        ds.setPassword("Tr0ub4dor&3");
        return ds;
    }
}
