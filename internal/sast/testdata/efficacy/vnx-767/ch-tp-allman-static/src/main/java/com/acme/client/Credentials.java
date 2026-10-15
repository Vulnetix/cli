package com.acme.client;

public class Credentials
{
    private static String clientSecret = System.getenv("CLIENT_SECRET");

~>    public static String getClientSecret()
    {
        return clientSecret;
    }
}
