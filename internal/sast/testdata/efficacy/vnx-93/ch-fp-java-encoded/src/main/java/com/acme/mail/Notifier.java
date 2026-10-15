package com.acme.mail;

import java.io.PrintWriter;
import javax.servlet.http.HttpServletRequest;
import javax.mail.internet.MimeUtility;

public class Notifier {
    private final PrintWriter smtp;

    public Notifier(PrintWriter smtp) {
        this.smtp = smtp;
    }

    public void notify(HttpServletRequest request) throws Exception {
        String subject = MimeUtility.encodeText(request.getParameter("subject"), "UTF-8", "B");
        smtp.print("Subject: " + subject + "\r\n");
        String count = String.valueOf(Integer.parseInt(request.getParameter("n")));
        smtp.print("X-Count: " + count + "\r\n");
    }
}
