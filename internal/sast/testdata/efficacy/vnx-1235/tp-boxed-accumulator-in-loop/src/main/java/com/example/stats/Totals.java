package com.example.stats;

import java.util.Iterator;
import java.util.List;

public class Totals {
    long sum(List<Long> values) {
        Long sum = 0L;
        for (long v : values) {
~>            sum += v;
        }
        return sum;
    }

    int count(Iterator<String> it) {
        Integer count = 0;
        while (it.hasNext()) {
            it.next();
~>            count++;
        }
        return count;
    }

    double price(List<Item> items) {
        Double total = 0.0;
        for (Item p : items)
~>            total = total + p.getPrice();
        return total;
    }
}
