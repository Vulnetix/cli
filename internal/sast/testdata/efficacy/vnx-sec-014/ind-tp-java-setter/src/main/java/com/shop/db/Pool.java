package com.shop.db;

import com.zaxxer.hikari.HikariConfig;

public class Pool {
    public static HikariConfig config() {
        HikariConfig cfg = new HikariConfig();
        cfg.setJdbcUrl("jdbc:postgresql://db.internal:5432/shop");
        cfg.setUsername("shop");
~>        cfg.setPassword("Wn7$kLq92xPz");
        return cfg;
    }
}
