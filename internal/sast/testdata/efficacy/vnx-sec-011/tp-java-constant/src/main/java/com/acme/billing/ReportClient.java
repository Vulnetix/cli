package com.acme.billing;

public final class ReportClient {
    private static final String TOKEN =
~>        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdmMtYmlsbGluZyIsInJvbGUiOiJzZXJ2aWNlIiwiaWF0IjoxNzYwMDAwMDAwfQ.@@sample:[A-Za-z0-9_\-]{43}@@";

    public String authHeader() {
        return "Bearer " + TOKEN;
    }
}
