package com.acme;

import java.util.Map;

public class Lookup {
~>    private Map<String, String> cache;

    public String find(String id) {
        return cache.get(id);
    }
}
