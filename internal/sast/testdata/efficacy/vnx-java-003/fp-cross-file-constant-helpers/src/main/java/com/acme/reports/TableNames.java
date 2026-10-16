package com.acme.reports;

public class TableNames {
    private static final String AUDIT = "audit_log";

    public String reports() {
        return "reports";
    }

    public static String audit() {
        return AUDIT;
    }

    public String archive() {
        String prefix = "old_";
        return prefix + reports();
    }
}
