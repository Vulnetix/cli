package com.acme.a;

public class Uploader {
~>    private static final String BUCKET_URL =
        "https://storage.acme.example/uploads";

    public String target(String name) {
        return BUCKET_URL + "/" + name;
    }
}
