package com.acme.mail;

import java.util.Properties;

public class SmtpSettings {
    public String host = "smtp.example.com";
    public int port = 587;
    public String username;
~>    public String password;
~>    public static String apiKey = System.getenv("MAIL_API_KEY");
    public boolean starttls = true;

    public Properties toProperties() {
        Properties p = new Properties();
        p.put("mail.smtp.host", host);
        p.put("mail.smtp.port", String.valueOf(port));
        return p;
    }
}
