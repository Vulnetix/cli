package com.shop.web;

public class AccessPolicy {

    public Level levelFor(User user) {
        if (user.hasRole("ADMIN")) {
            return Level.FULL;
        } else if (user.hasRole("SUPPORT")) {
            if (user.hasRole("ADMIN")) {
                return Level.AUDIT;
            } else if (user.isActive()) {
                return Level.READ;
            }
        } else if (user.hasRole("AUDITOR")) {
            return Level.AUDIT;
        }
        return Level.NONE;
    }

    public boolean canRefund(User user, Order order) {
        if (user.isAuthenticated() && order.isPaid()) {
            return order.getOwnerId().equals(user.getId());
        }
        return user != null && user.getId() != null;
    }
}
