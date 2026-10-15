package com.acme.web;

import javax.servlet.http.HttpServletRequest;

public class Split {
    public int perPart(HttpServletRequest request, int total) {
        int parts = Integer.valueOf(request.getParameter("parts"));
~>        return total / parts;
    }
}
