package com.acme.config;

import java.io.Console;
import java.util.Properties;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class SecretsConfig {

    @Value("${spring.datasource.password}")
    private String password;

    @Value("${mail.smtp.password:}")
    private String smtpPassword;

    private final SecretStore secrets;

    public SecretsConfig(SecretStore secrets) {
        this.secrets = secrets;
    }

    String dbPassword() {
        String dbPassword = System.getenv("DB_PASSWORD");
        return dbPassword;
    }

    String keystorePassword() {
        String keystorePassword = System.getProperty("javax.net.ssl.keyStorePassword", "");
        return keystorePassword;
    }

    String mailPassword(Properties props) {
        String password = props.getProperty("mail.password");
        return password;
    }

    char[] prompt(Console console) {
        char[] pwd = console.readPassword("Password: ");
        return pwd;
    }

    void configure(com.zaxxer.hikari.HikariConfig cfg) {
        cfg.setPassword(secrets.lookup("reporting/db"));
        cfg.setPassword(this.password);
    }
}
