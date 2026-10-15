package com.acme.model;

public class Credentials {
    private String password;
    private String apiKey;

    public String describe() {
        String note = "implements Serializable with private String password;";
        return note;
    }
}
