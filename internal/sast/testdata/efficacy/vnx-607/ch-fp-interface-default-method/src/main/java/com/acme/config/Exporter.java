package com.acme.config;

import java.util.ArrayList;
import java.util.List;

public interface Exporter {
    List<String> EXTENSIONS = List.of("csv", "tsv");

    String name();

    default List<String> describe() {
        List<String> out = new ArrayList<>();
        out.add(name());
        return out;
    }
}
