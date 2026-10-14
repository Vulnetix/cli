package com.acme.fetch;

import javax.servlet.http.HttpServletRequest;

public class Doc {
    // new URL(request.getParameter("url")).openStream() is SSRF.
    private static final String NOTE = "restTemplate.getForObject(request.getParameter(\"u\"), String.class)";

    public String note(HttpServletRequest request) {
        String name = request.getParameter("name");
        return NOTE + name;
    }
}
