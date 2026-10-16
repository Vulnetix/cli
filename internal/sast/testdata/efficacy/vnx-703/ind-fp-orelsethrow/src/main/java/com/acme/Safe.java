package com.acme;

import java.util.Optional;

public class Safe {
    Order a(Long id) { return orders.findById(id).orElseThrow(() -> new NotFound(id)); }
    Order b(Long id) { return orders.findById(id).orElse(null); }
    void c(Long id) { orders.findById(id).ifPresent(this::use); }
    String d(String login) {
        Optional<Account> a = repo.findByLogin(login);
        if (a.isEmpty()) {
            return "";
        }
        return a.get().getName();
    }
}
