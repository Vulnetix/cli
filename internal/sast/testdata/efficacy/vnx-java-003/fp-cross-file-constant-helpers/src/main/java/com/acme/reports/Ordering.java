package com.acme.reports;

public abstract class Ordering {
    public String column(String requested) {
        return "created_at";
    }
}
