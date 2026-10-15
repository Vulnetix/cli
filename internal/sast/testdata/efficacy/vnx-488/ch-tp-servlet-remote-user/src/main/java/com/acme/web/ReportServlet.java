package com.acme.web;

import javax.servlet.http.*;

public class ReportServlet extends HttpServlet {
    private String currentUser;
    private String lastQuery;

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
~>        currentUser = req.getRemoteUser();
~>        lastQuery = req.getQueryString();
        resp.getWriter().print(render(currentUser, lastQuery));
    }
}
