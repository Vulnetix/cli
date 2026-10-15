package com.acme.web;

public class Debug {
    void dump(javax.servlet.http.HttpServletRequest request) {
~>        System.out.println("Cookie: " + request.getHeader("cookie"));
    }
}
