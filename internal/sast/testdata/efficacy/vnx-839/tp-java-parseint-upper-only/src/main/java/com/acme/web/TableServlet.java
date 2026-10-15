package com.acme.web;

public class TableServlet extends HttpServlet {
    private final String[] rows = new String[64];

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        int row = Integer.parseInt(request.getParameter("row"));
~>        if (row < rows.length) {
            response.getWriter().print(rows[row]);
        }
    }

    protected void doPut(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        int slot = Integer.valueOf(req.getParameter("slot"));
~>        if (slot > 63) {
            resp.sendError(400);
            return;
        }
        rows[slot] = req.getParameter("v");
    }
}
