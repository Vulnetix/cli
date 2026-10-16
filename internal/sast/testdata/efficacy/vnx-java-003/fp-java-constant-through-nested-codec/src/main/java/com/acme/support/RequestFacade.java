package com.acme.support;

public class RequestFacade {
    private final javax.servlet.http.HttpServletRequest request;

    public RequestFacade(javax.servlet.http.HttpServletRequest request) {
        this.request = request;
    }

    public String param(String name) {
        return request.getParameter(name);
    }

    public String fixed(String name) {
        return "default";
    }
}
