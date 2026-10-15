package com.acme.web;

import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ReturnController {
    private static final String BASE = "/portal/";

    public void afterLogin(HttpServletRequest request, HttpServletResponse httpResponse) throws IOException {
        String next = request.getParameter("next");
        String target = BASE + next;
~>        httpResponse.sendRedirect(target);
    }
}
