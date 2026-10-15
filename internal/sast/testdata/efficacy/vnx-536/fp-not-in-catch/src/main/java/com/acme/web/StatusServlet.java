package com.acme.web;

public class StatusServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Status s = monitor.status();
        response.getWriter().println(s.getMessage());
        response.getWriter().println(s.toString());
    }

    void validate(String e) throws IOException {
        response.getWriter().println(e);
    }
}
