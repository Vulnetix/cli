package com.acme.mail;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class RelayServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String recipient = request.getParameter("to");
        String text = request.getParameter("text");

        try (Socket socket = new Socket("mail.internal", 25);
             BufferedWriter out = new BufferedWriter(
                 new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.US_ASCII))) {
            out.write("HELO app.internal\r\n");
            out.write("MAIL FROM:<relay@example.org>\r\n");
~>            out.write("RCPT TO:<" + recipient + ">\r\n");
            out.write("DATA\r\n");
            out.write("\r\n");
            out.write(text);
            out.write("\r\n.\r\n");
            out.write("QUIT\r\n");
            out.flush();
        }
        response.setStatus(202);
    }
}
