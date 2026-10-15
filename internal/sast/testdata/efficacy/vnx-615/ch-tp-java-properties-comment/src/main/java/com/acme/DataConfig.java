package com.acme;

import javax.sql.DataSource;

public class DataConfig {
    /**
     * Connects with the reporting account.
~>     * spring.datasource.password=Rep0rt!ng
     */
    public DataSource dataSource() {
        return Pools.create(System.getenv("DB_URL"));
    }
}
