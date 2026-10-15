package com.acme.api;

public class Client {
~>    public static final String API_BASE_URL = "https://api.acme.example/v2";

    String url(String p) { return API_BASE_URL + p; }
}
