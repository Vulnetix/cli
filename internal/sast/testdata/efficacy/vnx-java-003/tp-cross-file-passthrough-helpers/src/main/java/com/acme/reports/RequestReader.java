package com.acme.reports;

import javax.servlet.http.HttpServletRequest;

public class RequestReader {
    private final HttpServletRequest request;

    public RequestReader(HttpServletRequest request) {
        this.request = request;
    }

    public String param(String name) {
        return request.getParameter(name);
    }

    public String header() {
        return request.getHeader("X-Filter");
    }
}
