package com.acme.model;

import java.util.Collections;
import java.util.List;
import java.util.Map;

public class Catalog {
    private final List<String> names = List.of("a", "b");
    private final Map<String, String> labels = Collections.unmodifiableMap(load());
    private String title;
    private int size;

    public List<String> getNames() {
        return names;
    }

    public Map<String, String> getLabels() {
        return labels;
    }

    public String getTitle() {
        return title;
    }

    public int getSize() {
        return size;
    }
}
