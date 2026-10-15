package com.acme.db;

public class Pool {
    static final com.zaxxer.hikari.HikariDataSource DS;
    static final Runnable HOOK;

    static {
        com.zaxxer.hikari.HikariConfig cfg =
~>                new com.zaxxer.hikari.HikariConfig();
        cfg.setJdbcUrl(System.getenv("JDBC_URL"));
~>        DS = new com.zaxxer.hikari.HikariDataSource(cfg);
~>        HOOK = new Runnable() {
            @Override
            public void run() {
                DS.close();
            }
        };
    }
}
