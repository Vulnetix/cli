package com.acme.reports;

public class ByRequest extends Ordering {
    @Override
    public String column(String requested) {
        String picked = requested;
        return picked;
    }
}
