package com.acme.shop;

import java.util.Comparator;
import java.util.List;

public class Reports {
    public Order newest(List<Order> list, String customer) {
~>        return list.stream().filter(o -> o.customer().equals(customer)).findFirst().get();
    }

    public Order biggest(List<Order> list) {
~>        return list.stream().max(Comparator.comparing(Order::total)).get();
    }

    public Order any(List<Order> list) {
~>        return list.parallelStream().findAny().get();
    }

    public int topQty(List<Order> list) {
~>        return list.stream().mapToInt(Order::qty).max().getAsInt();
    }

    public double meanTotal(List<Order> list) {
~>        return list.stream().mapToDouble(Order::total).average().getAsDouble();
    }

    public Integer sum(List<Integer> xs) {
~>        return xs.stream().reduce(Integer::sum).get();
    }
}
