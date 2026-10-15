package com.acme;

public class OrderServletTest {
    void f(HttpServletResponse response) throws Exception {
        try {
            run();
        } catch (Exception e) {
            response.getWriter().println(e.getMessage());
        }
    }
}
