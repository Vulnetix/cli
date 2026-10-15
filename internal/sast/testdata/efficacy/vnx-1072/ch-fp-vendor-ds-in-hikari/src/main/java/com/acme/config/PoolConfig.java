package com.acme.config;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import javax.sql.DataSource;
import org.postgresql.ds.PGSimpleDataSource;

public class PoolConfig {
    public DataSource dataSource(String url) {
        PGSimpleDataSource target = new PGSimpleDataSource();
        target.setUrl(url);
        HikariConfig config = new HikariConfig();
        config.setDataSource(target);
        config.setMaximumPoolSize(20);
        return new HikariDataSource(config);
    }
}
