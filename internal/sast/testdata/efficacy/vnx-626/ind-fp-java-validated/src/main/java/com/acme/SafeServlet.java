package com.acme;

public class SafeServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse resp) {
        String name = request.getParameter("name");
        if (!name.matches("[A-Za-z0-9_]+")) { resp.sendError(400); return; }
        File f = new File("/var/reports", name + ".txt");
        File g = new File("/var/reports", "daily" + ".txt");
    }
}
