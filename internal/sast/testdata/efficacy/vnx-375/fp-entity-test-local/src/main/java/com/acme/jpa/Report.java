package com.acme.jpa;

import java.util.ArrayList;
import java.util.List;

public class Report {
    private List<String> rows;

    public List<String> build() {
        List<String> rows = new ArrayList<>();
        rows.add("header");
        return rows;
    }
}
