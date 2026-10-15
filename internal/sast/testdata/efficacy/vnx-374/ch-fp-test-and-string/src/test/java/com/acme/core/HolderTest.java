package com.acme.core;

import java.util.List;

public class HolderTest {
    private List<String> captured;

    public void capture(List<String> values) {
        this.captured = values;
    }

    public String describe() {
        return "public void set(List<String> v) { this.v = v; }";
    }
}
