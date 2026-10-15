package com.example;

import com.zaxxer.hikari.HikariConfig;
import java.net.ServerSocket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class PoolConfig {
    private final ExecutorService pool =
        Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors() * 2);

    public HikariConfig config(int poolSize) {
        HikariConfig config = new HikariConfig();
        config.setMaximumPoolSize(20);
        config.setMinimumIdle(1);
        config.setMaximumPoolSize(poolSize);
        return config;
    }

    public void serve(ServerSocket server) throws Exception {
        pool.submit(() -> server.accept());
    }
}
