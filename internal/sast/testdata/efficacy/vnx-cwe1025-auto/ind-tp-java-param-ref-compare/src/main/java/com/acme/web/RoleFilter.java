package com.acme.web;

import javax.servlet.http.HttpServletRequest;

public class RoleFilter {
    private final String expectedMode;

    public RoleFilter(String expectedMode) {
        this.expectedMode = expectedMode;
    }

    public boolean sameMode(HttpServletRequest request) {
~>        return request.getParameter("mode") == expectedMode;
    }
}
