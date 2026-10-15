package com.acme.report;

public class Queries {
    public String overdue() {
        return """
            SELECT id FROM invoice
            WHERE days_late > 45 AND amount > 2500
            UNION SELECT id FROM credit WHERE amount > 2500
            UNION SELECT id FROM refund WHERE amount > 2500
            """;
    }
}
