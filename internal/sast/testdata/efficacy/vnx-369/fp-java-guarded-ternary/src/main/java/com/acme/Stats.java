package com.acme;

import javax.servlet.http.HttpServletRequest;

public class Stats {
    public int pages(HttpServletRequest request, int total) {
        int size = Integer.parseInt(request.getParameter("size"));
        if (size <= 0) {
            throw new IllegalArgumentException("size");
        }
        return total / size;
    }

    public int safe(HttpServletRequest request, int total) {
        int per = Integer.parseInt(request.getParameter("per"));
        return per == 0 ? 0 : total / per;
    }
}
