package com.acme;

import java.util.List;

public class Counter {
    private int count;
    private boolean ready;
    private final Formatter formatter;
    private String name;
    private List<String> tags;

    public Counter(Formatter formatter) {
        this.formatter = formatter;
    }

    public String next() {
        count++;
        ready = true;
        return formatter.format(count);
    }

    public String greet(String name) {
        return name.trim();
    }

    public int size(List<String> all) {
        return all.stream().filter(tags -> tags.isEmpty()).toList().size();
    }
}
