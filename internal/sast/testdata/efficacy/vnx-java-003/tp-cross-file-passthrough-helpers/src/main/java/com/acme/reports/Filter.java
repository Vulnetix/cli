package com.acme.reports;

public class Filter {
    private final String clause;

    public Filter(String clause) {
        this.clause = clause;
    }

    public String clause() {
        return clause;
    }
}
