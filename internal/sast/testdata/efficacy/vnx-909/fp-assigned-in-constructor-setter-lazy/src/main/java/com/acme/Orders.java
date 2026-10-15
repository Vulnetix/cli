package com.acme;

import java.util.HashMap;
import java.util.Map;

public class Orders {
    private OrderRepository repo;
    private Clock clock;
    private Map<String, Order> cache;
    private Mailer mailer;

    {
        mailer = new Mailer();
    }

    public Orders(OrderRepository repo) {
        this.repo = repo;
    }

    public void setClock(Clock c) {
        clock = c;
    }

    public Order get(String id) {
        if (cache == null) {
            cache = new HashMap<>();
        }
        mailer.ping();
        return cache.computeIfAbsent(id, k -> repo.find(k, clock.now()));
    }
}
