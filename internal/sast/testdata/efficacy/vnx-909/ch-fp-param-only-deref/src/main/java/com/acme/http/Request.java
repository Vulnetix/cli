package com.acme.http;

import java.util.Map;

public class Request {
    private Map<String, String> headers;

    public int count(Map<String, String> headers) {
        return headers.size();
    }

    public boolean has(Map<String, String> headers, String name) {
        return headers.containsKey(name);
    }
}
