package com.acme.mail;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.Socket;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class RelayServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String rcpt = request.getParameter("rcpt");
        try (Socket s = new Socket("mail.internal", 25);
             PrintWriter out = new PrintWriter(s.getOutputStream())) {
~>            out.print("RCPT TO:<" + rcpt + ">\r\n");
~>            out.print("Subject: " + request.getParameter("subject") + "\r\n");
        }
    }
}
