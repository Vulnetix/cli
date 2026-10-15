package com.example.orders;

import javax.ejb.EJB;
import javax.ejb.Stateless;

// EJB spec: beans must not call getClassLoader() or create a new URLClassLoader(...)
@Stateless
public class OrderService {
    @EJB
    private InventoryService inventory;

    private static final String NOTE = "do not use setContextClassLoader here";

    public boolean place(String sku) {
        return inventory.reserve(sku);
    }
}
