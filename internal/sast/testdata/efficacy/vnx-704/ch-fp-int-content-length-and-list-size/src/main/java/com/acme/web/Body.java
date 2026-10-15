package com.acme.web;

import java.util.List;
import javax.servlet.http.HttpServletRequest;

public class Body {

    public byte[] read(HttpServletRequest request) {
        int n = (int) request.getContentLength();
        return new byte[n];
    }

    public int total(List<String> names) {
        long total = names.size();
        return (int) total;
    }
}
