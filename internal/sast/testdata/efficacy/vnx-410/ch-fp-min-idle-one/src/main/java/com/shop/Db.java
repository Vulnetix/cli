package com.shop;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

public final class Db {
    public static HikariDataSource create(String url) {
        HikariConfig cfg = new HikariConfig();
        cfg.setJdbcUrl(url);
        cfg.setMaximumPoolSize(32);
        cfg.setMinimumIdle(1);
        cfg.setMaxLifetime(1800000);
        return new HikariDataSource(cfg);
    }
}
