package com.acme.reports;

public class ByName extends Ordering {
    @Override
    public String column(String requested) {
        return "name";
    }
}
