package com.acme.config;

public class MailSettings {
    public String host = "smtp.acme.local";
    public int port = 587;
    public String username;
~>    public String password;
~>    public static String apiKey = System.getenv("MAIL_API_KEY");
~>    public String clientSecret;
}
