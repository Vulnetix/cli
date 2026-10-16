package com.acme;

import java.util.Comparator;
import java.util.List;

public class Reports {
    Order biggest(List<Order> list) {
~>        return list.stream().max(Comparator.comparing(Order::total)).get();
    }

    int highest(int[] xs) {
~>        return java.util.Arrays.stream(xs).max().getAsInt();
    }
}
