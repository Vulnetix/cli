package com.acme.svc;

import java.util.logging.Level;
import java.util.logging.Logger;

public class OrderService {
    private static final Logger LOG = Logger.getLogger(OrderService.class.getName());

    public void submit(Order o) {
        try {
            o.validate();
        } catch (IllegalStateException e) {
            LOG.log(Level.WARNING, "invalid order", e);
        }
        try {
            o.persist();
        } catch (RuntimeException e) {
            throw new OrderException("persist failed", e);
        }
        try {
            o.notifyCustomer();
        } catch (RuntimeException e) { metrics.increment("notify.failed"); }
    }
}
