package com.acme.http;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

public class Response {
    private final List<String> lines = new ArrayList<>();
    private final Date at = new Date();
    private final int[] codes = {200, 201};
    private static final List<String> DEFAULTS = List.of("a", "b");

    public List<String> getLines() {
        return Collections.unmodifiableList(lines);
    }

    public Date getAt() {
        return new Date(at.getTime());
    }

    public int[] getCodes() {
        return codes.clone();
    }

    public static List<String> defaults() {
        return DEFAULTS;
    }

    public List<String> copyLines() {
        return new ArrayList<>(lines);
    }
}
