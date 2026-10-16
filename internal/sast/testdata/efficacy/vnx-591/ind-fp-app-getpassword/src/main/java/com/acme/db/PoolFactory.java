package com.acme.db;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

public class PoolFactory {

    public HikariDataSource create(DatabaseSettings settings) {
        HikariConfig cfg = new HikariConfig();
        cfg.setJdbcUrl(settings.getUrl());
        cfg.setUsername(settings.getUsername());
        String password = settings.getPassword();
        cfg.setPassword(password);
        cfg.setMaximumPoolSize(settings.getPoolSize());
        return new HikariDataSource(cfg);
    }
}
