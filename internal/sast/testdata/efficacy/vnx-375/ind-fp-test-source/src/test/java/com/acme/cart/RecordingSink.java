package com.acme.cart;

import java.util.ArrayList;
import java.util.List;

public class RecordingSink {
    private final List<String> events = new ArrayList<>();

    public List<String> getEvents() {
        return events;
    }
}
