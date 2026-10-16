package app;

import javax.servlet.http.*;

public class HitServlet extends HttpServlet {
    private int hits;
    private String lastUser;

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
~>        hits++;
~>        lastUser = req.getParameter("user");
    }
}
