package com.acme.mail;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.util.Properties;
import javax.mail.Authenticator;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;

public final class SmtpSender {
    private static final String SMTP_USER = "relay";
~>    private static final String SMTP_PASSWORD = "mailRelay2024";

    private String adminPwd;

    SmtpSender() {
~>        this.adminPwd = "Adm1nPwd!";
    }

    Session session(Properties props) {
        return Session.getInstance(props, new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(SMTP_USER, SMTP_PASSWORD.toCharArray());
            }
        });
    }

    KeyStore signingStore() throws Exception {
~>        char[] keyPassphrase = "f1l3-k3y-pass".toCharArray();
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream in = new FileInputStream("/etc/acme/signing.p12")) {
            ks.load(in, keyPassphrase);
        }
        return ks;
    }
}
