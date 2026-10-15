package com.acme.report;

import java.util.List;

public class Summary {

    Long total(Order order) {
        Long total = 0L;
        total = order.getAmount();
        return total;
    }

    int rows(List<Row> rows) {
        int total = 0;
        for (Row r : rows) {
            total += r.size();
        }
        return total;
    }
}
