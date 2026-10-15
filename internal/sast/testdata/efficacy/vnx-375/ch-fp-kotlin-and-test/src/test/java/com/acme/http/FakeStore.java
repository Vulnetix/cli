package com.acme.http;

import java.util.ArrayList;
import java.util.List;

public class FakeStore {
    private final List<String> saved = new ArrayList<>();

    public List<String> getSaved() {
        return saved;
    }
}
