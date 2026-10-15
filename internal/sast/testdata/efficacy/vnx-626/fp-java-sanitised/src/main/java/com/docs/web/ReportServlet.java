package com.docs.web;

public class ReportServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String name = request.getParameter("name");
        if (name == null || !name.matches("[A-Za-z0-9_-]+")) {
            response.sendError(400);
            return;
        }
        File f = new File(reportDir, name + ".txt");
        File g = new File(reportDir, "summary.txt");
        String label = request.getParameter("label") + ".txt";
    }
}
