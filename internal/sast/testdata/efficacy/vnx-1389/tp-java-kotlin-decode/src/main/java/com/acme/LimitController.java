package com.acme;

import javax.servlet.http.HttpServletRequest;

public class LimitController {
    public int limit(HttpServletRequest request) {
~>        int limit = Integer.decode(request.getParameter("limit"));
        return Math.min(limit, 100);
    }

    public long id(String raw) {
~>        return Long.decode(raw.trim());
    }
}
