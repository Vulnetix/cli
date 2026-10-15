package com.acme.http;

import java.util.Map;

public class Request {
~>    private Map<String, String> headers;

    public void addAll(Map<String, String> headers) {
        this.headers.putAll(headers);
    }

    public String header(String name) {
        return this.headers.get(name);
    }
}
