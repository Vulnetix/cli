package com.acme.web;

public class RequestContext {
    private String userName;

    public RequestContext(HttpServletRequest request) {
        userName = request.getParameter("user");
    }

    void refresh(HttpServletRequest request) {
        this.userName = request.getRemoteUser();
    }
}
