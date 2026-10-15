package com.acme.jobs;

public class SyncJob {
~>    private static final String API_BASE_URL =
        "https://api.acme.example/v2";

    void run() { fetch(API_BASE_URL + "/sync"); }
}
