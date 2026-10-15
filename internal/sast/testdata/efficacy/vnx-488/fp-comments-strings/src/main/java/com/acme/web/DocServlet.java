package com.acme.web;

public class DocServlet extends HttpServlet {
    private String note;

    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        // note = request.getParameter("n");  never store request data in a field
        String help = "note = request.getParameter(x)";
        response.getWriter().println(help);
    }
}
