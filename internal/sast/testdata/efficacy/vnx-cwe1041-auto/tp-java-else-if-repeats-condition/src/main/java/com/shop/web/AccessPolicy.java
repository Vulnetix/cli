package com.shop.web;

public class AccessPolicy {

    public Level levelFor(User user) {
        if (user.hasRole("ADMIN")) {
            return Level.FULL;
        } else if (user.hasRole("SUPPORT")) {
            return Level.READ;
~>        } else if (user.hasRole("ADMIN")) {
            return Level.AUDIT;
        }
        return Level.NONE;
    }

    public boolean canRefund(User user, Order order) {
~>        if (user.isAuthenticated() && user.isAuthenticated()) {
            return order.getOwnerId().equals(user.getId());
        }
        return false;
    }
}
