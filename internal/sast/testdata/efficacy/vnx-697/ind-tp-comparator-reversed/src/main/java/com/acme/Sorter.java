package com.acme;

import java.util.Comparator;

public class Sorter {
    private final Comparator<Order> byPrice = Comparator.comparing(Order::price);

    boolean firstIsCheaper(Order a, Order b) {
~>        return -1 == byPrice.compare(a, b);
    }

    boolean cmpStr(String x, String y) {
~>        return x.compareToIgnoreCase(y) != -1;
    }
}
