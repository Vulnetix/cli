package com.acme.ops;

import javax.servlet.http.HttpServletRequest;

public class Reader {
    private final HttpServletRequest request;

    public Reader(HttpServletRequest request) {
        this.request = request;
    }

    public String fromParameter(String name) {
        return request.getParameter(name);
    }

    public String fromHeader() {
        String value = request.getHeader("X-Job");
        return value;
    }

    public String pick(HttpServletRequest other) {
        return other.getParameter("job");
    }
}
