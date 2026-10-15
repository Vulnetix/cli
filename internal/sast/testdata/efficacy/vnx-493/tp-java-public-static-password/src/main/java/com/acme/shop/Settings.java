package com.acme.shop;

public class Settings {
~>    public static String DB_PASSWORD = System.getenv("DB_PW");
~>    public static String apiKey;
~>    static public boolean isAdmin = false;
~>	public static volatile String authToken;
}
