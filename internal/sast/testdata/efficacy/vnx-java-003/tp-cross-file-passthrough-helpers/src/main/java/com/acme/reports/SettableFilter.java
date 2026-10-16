package com.acme.reports;

public class SettableFilter {
    private String clause;

    public SettableFilter(String clause) {
        this.clause = clause;
    }

    public void replace(String clause) {
        this.clause = clause;
    }

    public String clause() {
        return clause;
    }
}
