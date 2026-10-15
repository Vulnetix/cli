package com.shop.web;

import java.util.List;
import javax.servlet.http.HttpServletRequest;

final class Paging {
    private static final int MAX_PAGE = 100;

    static int pageSize(HttpServletRequest req) {
        int n = Integer.parseInt(req.getParameter("size"));
        return Math.min(n, MAX_PAGE);
    }

    static void fill(List<Integer> out, int n) {
        for (int i = 0; i < n; i++) {
            out.add(i);
        }
    }
}
