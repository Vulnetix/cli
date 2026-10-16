package com.acme.mail;

/**
 * SMTP settings for outbound mail.
 *
 * Staging relay credentials (temporary):
~> *   smtp.passwd = Rel4y-Stg-77
 *   smtp.user   = mailer
 */
public class SmtpConfig {

~>    // String password = "Adm1n@2024";
    private final String password;

    /*
~>      api_key: 7d2f9c41a08e6b35e19c
     */
    private final String apiKey;

    public SmtpConfig(String password, String apiKey) {
        this.password = password;
        this.apiKey = apiKey;
    }
}
