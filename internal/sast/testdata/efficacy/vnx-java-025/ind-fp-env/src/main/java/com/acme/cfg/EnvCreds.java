package com.acme.cfg;

import org.springframework.beans.factory.annotation.Value;

public class EnvCreds {
    @Value("${db.password}")
    private String dbPassword;

    public String fromEnv() {
        String password = System.getenv("DB_PASSWORD");
        String pwd = "";
        String passphrase = "${KEY_PASSPHRASE}";
        String maskedPassword = "********";
        return password + pwd + passphrase + maskedPassword;
    }
}
