package com.acme;

import javax.servlet.http.HttpServletRequest;

public class PageController {
    public int pages(HttpServletRequest request, int total) {
        int size = Integer.parseInt(request.getParameter("size"));
~>        return total / size;
    }

    public int bucket(HttpServletRequest request, int id) {
        String raw = request.getParameter("buckets");
        long buckets = Long.parseLong(raw);
~>        return (int) (id % buckets);
    }
}
