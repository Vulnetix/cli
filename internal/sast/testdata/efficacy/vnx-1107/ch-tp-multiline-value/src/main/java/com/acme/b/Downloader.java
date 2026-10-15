package com.acme.b;

public final class Downloader {
~>    static final String BUCKET_URL = "https://storage.acme.example/uploads";

    public String source(String name) {
        return BUCKET_URL + "/" + name;
    }
}
