package com.shop.report;

public class Totals {

    public long sum(List<Order> orders) {
        long total = 0;
        int count = 0;
        for (Order order : orders) {
            total += order.getAmount();
            count = count + 1;
        }
        return total;
    }

    public void print(List<Order> orders) {
        for (Order order : orders) {
            String line = order.getId() + ": ";
            line += order.getAmount();
            log.info(line);
        }
    }
}
