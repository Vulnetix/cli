package com.example;

import com.zaxxer.hikari.HikariConfig;

class RepositoryTest {
    HikariConfig config() {
        HikariConfig config = new HikariConfig();
        config.setMaximumPoolSize(1);
        return config;
    }
}
