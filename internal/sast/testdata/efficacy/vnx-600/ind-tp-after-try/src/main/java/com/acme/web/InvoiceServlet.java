package com.acme.web;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

public class InvoiceServlet extends HttpServlet {

    private InvoiceService invoices;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String idParam = req.getParameter("id");
        int year;
        try {
            year = Integer.parseInt(req.getParameter("year"));
        } catch (NumberFormatException e) {
            year = java.time.Year.now().getValue();
        }
~>        long id = Long.parseLong(idParam);
        resp.getWriter().write(invoices.render(id, year));
    }
}
