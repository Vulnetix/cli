package com.acme.http;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Request {
    @JsonProperty("headers")
    private Map<String, List<String>> headers;

    @JsonProperty("cookies") private List<String> cookies = new ArrayList<>();

    @Override
    public String toString() {
        return "Request";
    }

    @JsonIgnore
    public Map<String, List<String>> getHeaders() {
        if (headers == null) {
            headers = new HashMap<>();
        }
~>        return headers;
    }

    public List<String> cookies() {
~>        return this.cookies;
    }
}
