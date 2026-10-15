package com.acme.order;

import java.util.List;

class OrderBuilderTest {
    private List<String> captured;

    public void capture(List<String> items) {
        this.captured = items;
    }
}
