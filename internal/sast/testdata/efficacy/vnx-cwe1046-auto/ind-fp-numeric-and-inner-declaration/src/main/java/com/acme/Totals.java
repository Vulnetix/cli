package com.acme;

import java.util.List;

public class Totals {
    public String sum(List<Order> orders) {
        int total = 0;
        for (Order order : orders) {
            String line = order.getId() + ": ";
            line += order.getAmount();
            total += order.getQty();
            log(line);
        }
        return "total " + total;
    }
}
