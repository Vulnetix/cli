package com.acme;

import java.util.List;
import java.util.Map;

public class OrderService {
~>    public OrderService(
            OrderRepository orders,
            Map<String, List<Integer>> limits,
            CustomerRepository customers,
            PaymentGateway payments,
            final InventoryClient inventory,
            NotificationService notifier,
            AuditLog audit,
            Clock clock) {
    }

~>    protected <T extends Comparable<T>> List<T> merge(List<T> a, List<T> b, List<T> c,
            List<T> d, List<T> e, List<T> f, List<T> g, String... tags) throws Exception {
        return a;
    }
}
