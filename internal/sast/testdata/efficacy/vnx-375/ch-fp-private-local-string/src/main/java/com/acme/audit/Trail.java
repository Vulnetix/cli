package com.acme.audit;

import java.util.ArrayList;
import java.util.List;

public class Trail {
    private final List<String> entries = new ArrayList<>();
    private String owner;

    private List<String> raw() {
        return entries;
    }

    public String getOwner() {
        return owner;
    }

    public List<String> snapshot() {
        List<String> entries = new ArrayList<>(this.entries);
        return entries;
    }

    public String help() {
        // returns entries; to callers who ask
        return "use return entries; carefully";
    }
}
