package com.acme.web;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class BackServlet {
    public void back(HttpServletRequest request, HttpServletResponse response) {
        response.setStatus(HttpServletResponse.SC_FOUND);
~>        response.setHeader("Location", request.getHeader("Referer"));
    }
}
