package com.acme;

import org.junit.Test;

public class OrderTest {
    @Test
    public void loads() {
        Order o = orders.findById(1L).get();
        assert o != null;
    }
}
