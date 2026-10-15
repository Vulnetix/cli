package com.example;

import java.util.ArrayList;
import java.util.List;

public class Audit {
    private final List<String> events = new ArrayList<>();

    public void record(String event) {
~>        synchronized (new Object()) {
            events.add(event);
        }
    }
}
