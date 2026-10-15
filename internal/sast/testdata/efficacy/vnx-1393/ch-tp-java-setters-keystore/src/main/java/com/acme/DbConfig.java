package com.acme;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.util.Properties;
import com.zaxxer.hikari.HikariConfig;

public class DbConfig {
    public HikariConfig hikari(String url) {
        HikariConfig cfg = new HikariConfig();
        cfg.setJdbcUrl(url);
        cfg.setUsername("app");
~>        cfg.setPassword("postgres");
        return cfg;
    }

    public KeyStore trustStore(String path) throws Exception {
        KeyStore ks = KeyStore.getInstance("JKS");
        try (FileInputStream in = new FileInputStream(path)) {
~>            ks.load(in, "changeit".toCharArray());
        }
        return ks;
    }

    public Properties props() {
        Properties p = new Properties();
        p.setProperty("user", "svc");
~>        p.setProperty("password", "secret");
        return p;
    }
}
