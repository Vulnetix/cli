package com.acme.db;

class DbConfig {
    static String jdbcUrl = System.getenv("JDBC_URL");
~>    static String dbPassword = System.getenv("DB_PASSWORD");
~>    char[] keystorePassphrase;
~>    static String apiKey;
    int poolSize = 10;

    static void load(java.util.Properties p) {
        apiKey = p.getProperty("service.api.key");
    }
}
