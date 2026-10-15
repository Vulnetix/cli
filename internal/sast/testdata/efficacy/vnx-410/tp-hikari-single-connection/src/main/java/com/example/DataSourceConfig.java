package com.example;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

public class DataSourceConfig {
    public HikariDataSource dataSource(String url) {
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl(url);
~>        config.setMaximumPoolSize(1);
        config.setConnectionTimeout(30000);
        return new HikariDataSource(config);
    }
}
