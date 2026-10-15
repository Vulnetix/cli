package com.acme.shop;

public class Settings {
    public static final String PASSWORD_PARAM = "password";
    public final float price;
    private static String dbPassword;
    protected String apiKey;
    String role;

    public Settings(float price) {
        this.price = price;
    }
}
