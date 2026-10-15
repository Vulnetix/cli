package com.acme.web;

import javax.servlet.http.HttpServletRequest;

public class Pager {
    public int pages(HttpServletRequest req, int total) {
        int size = Integer.parseInt(req.getParameter("size"));
        if (size < 1) {
            throw new IllegalArgumentException("size");
        }
        return (total + size - 1) / size;
    }
}
