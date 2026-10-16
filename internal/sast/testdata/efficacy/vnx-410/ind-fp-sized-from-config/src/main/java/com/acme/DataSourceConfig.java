package com.acme;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.eclipse.jetty.util.thread.QueuedThreadPool;

public class DataSourceConfig {

    public HikariDataSource dataSource(AppSettings settings) {
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl(settings.dbUrl());
        config.setMaximumPoolSize(settings.dbPoolSize());
        config.setMinimumIdle(1);
        return new HikariDataSource(config);
    }

    public QueuedThreadPool httpThreads(AppSettings settings) {
        QueuedThreadPool threads = new QueuedThreadPool(Runtime.getRuntime().availableProcessors() * 8);
        threads.setMaxThreads(200);
        return threads;
    }
}
