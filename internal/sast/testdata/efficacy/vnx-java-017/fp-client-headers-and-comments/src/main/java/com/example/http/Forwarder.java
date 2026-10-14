package com.example.http;

import javax.servlet.http.HttpServletRequest;
import okhttp3.Request;

public class Forwarder {
    // response.setHeader("X-Lang", request.getParameter("lang")) would split the response
    /*
     * response.sendRedirect(request.getParameter("next"));
     */
    public Request build(HttpServletRequest request) {
        String auth = request.getHeader("Authorization");
        String doc = "call response.setHeader(name, request.getParameter(x)) only after stripping CRLF";
        return new Request.Builder()
            .url("https://upstream.example.com/api")
            .addHeader("Authorization", auth)
            .build();
    }
}
