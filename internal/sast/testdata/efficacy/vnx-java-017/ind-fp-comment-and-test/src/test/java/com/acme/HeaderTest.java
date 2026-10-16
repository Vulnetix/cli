package com.acme;
import javax.servlet.http.*;
public class HeaderTest {
    // response.setHeader("X-Echo", request.getParameter("x"));
    String doc = "response.addHeader(name, request.getHeader(\"X\"))";
    void ok(HttpServletResponse response) {
        response.setHeader("X-Test", "1");
    }
}
