package com.acme;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.junit.jupiter.api.BeforeAll;

class RepositoryIT {
    static HikariDataSource ds;

    @BeforeAll
    static void setUp() {
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl("jdbc:h2:mem:test");
        config.setMaximumPoolSize(1);
        ds = new HikariDataSource(config);
    }
}
