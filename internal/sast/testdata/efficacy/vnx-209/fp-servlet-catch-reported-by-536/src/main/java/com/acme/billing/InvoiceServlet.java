package com.acme.billing;

import java.io.IOException;
import java.io.PrintWriter;
import java.sql.SQLException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// Each of these writes the caught exception to the servlet response from
// inside its catch block. VNX-536 reports them; this rule leaves them to it.
public class InvoiceServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        try {
            signer.sign(request.getParameter("invoice"));
        } catch (java.security.NoSuchAlgorithmException
                | java.security.InvalidKeyException
                | java.security.SignatureException failure) {
            response.getWriter().println("Could not sign the invoice");
            failure.printStackTrace(response.getWriter());
            throw new ServletException(failure);
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        PrintWriter page = response.getWriter();
        try {
            invoices.store(request.getParameter("invoice"));
        } catch (SQLException dbError) {
            page.println("Store failed: " + dbError.getMessage());
        }
    }
}
