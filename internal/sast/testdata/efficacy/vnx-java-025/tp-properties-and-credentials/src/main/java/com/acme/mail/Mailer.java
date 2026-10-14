package com.acme.mail;

import java.net.PasswordAuthentication;
import java.util.Properties;
import org.apache.http.auth.UsernamePasswordCredentials;

public class Mailer {
    Properties props() {
        Properties p = new Properties();
        p.put("mail.smtp.user", "noreply");
~>        p.put("mail.smtp.password", "smtp-Pa55");
~>        p.setProperty("password", "Winter2024");
        return p;
    }

    PasswordAuthentication auth() {
~>        return new PasswordAuthentication("noreply", "smtp-Pa55".toCharArray());
    }

    UsernamePasswordCredentials creds() {
~>        return new UsernamePasswordCredentials("api", "apiP@ss1");
    }
}
