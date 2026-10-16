package com.acme;

import javax.servlet.http.*;

public class PageServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String page = request.getParameter("page");
~>        request.getRequestDispatcher("/WEB-INF/views/" + page + ".jsp").forward(request, response);
    }
}
