package com.acme.files;

import java.io.*;
import javax.servlet.http.*;

public class InvoiceServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        long id = Long.parseLong(request.getParameter("id"));
        File f = new File("/srv/invoices", id + ".pdf");
        int year = Integer.parseInt(request.getParameter("year"));
        FileInputStream in = new FileInputStream(new File("/srv/archive/" + year + ".zip"));
    }
}
