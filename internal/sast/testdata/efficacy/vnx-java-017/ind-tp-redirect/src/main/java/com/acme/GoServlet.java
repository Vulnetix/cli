package com.acme;
import javax.servlet.http.*;
public class GoServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse res) throws java.io.IOException {
        String next = req.getParameter("next");
~>        res.sendRedirect(next);
    }
}
