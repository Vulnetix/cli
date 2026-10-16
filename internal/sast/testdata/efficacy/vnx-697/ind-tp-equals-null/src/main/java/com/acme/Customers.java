package com.acme;

public class Customers {
    void check(Customer c) {
~>        if (c.getRegion().equals(null)) {
            throw new IllegalArgumentException("no region");
        }
    }
}
