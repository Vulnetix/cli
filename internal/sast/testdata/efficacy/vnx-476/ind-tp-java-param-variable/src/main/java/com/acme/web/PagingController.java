package com.acme.web;

import javax.servlet.http.HttpServletRequest;

public class PagingController {
    public int page(HttpServletRequest req) {
        String page = req.getParameter("page");
        int base = 1;
~>        return base + Integer.parseInt(page.trim());
    }
}
