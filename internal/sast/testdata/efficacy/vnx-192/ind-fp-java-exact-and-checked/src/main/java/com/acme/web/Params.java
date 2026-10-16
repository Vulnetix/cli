package com.acme.web;

import javax.servlet.http.HttpServletRequest;

final class Params {

    private Params() {}

    static int maxBytes(HttpServletRequest req) {
        return Math.toIntExact(Long.parseLong(req.getParameter("max")));
    }

    static byte quality(HttpServletRequest req) {
        int q = Integer.parseInt(req.getParameter("q"));
        if (q < Byte.MIN_VALUE || q > Byte.MAX_VALUE) {
            throw new IllegalArgumentException("q out of range");
        }
        return (byte) q;
    }

    static long offset(HttpServletRequest req) {
        long off = (long) Integer.parseInt(req.getParameter("offset"));
        return off;
    }
}
