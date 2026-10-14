package com.acme.config;

import java.sql.Connection;
import java.sql.DriverManager;
import org.springframework.beans.factory.annotation.Value;

public class DbConfig {
    @Value("${datasource.password}")
    private String dataSourcePassword;

    private final String password = System.getenv("DB_PASSWORD");
    private static final String PASSWORD_ENV = "DB_PASSWORD";
    private static final String passwordProperty = "spring.datasource.password";
    private String adminPassword = "";
    private String placeholderPassword = "${ADMIN_PASSWORD}";
    private char[] keystorePassword = System.getenv("KS_PASS").toCharArray();

    Connection open(String url, String user, String pass) throws Exception {
        String dbPassword = System.getProperty("db.password");
        return DriverManager.getConnection(url, user, dbPassword);
    }

    Connection open2(String url) throws Exception {
        return DriverManager.getConnection(url, "app", password);
    }
}
