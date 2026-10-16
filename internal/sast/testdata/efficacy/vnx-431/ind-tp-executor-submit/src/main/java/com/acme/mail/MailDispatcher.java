package com.acme.mail;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MailDispatcher {
    private final ExecutorService mailers = Executors.newFixedThreadPool(4);
    private final SmtpClient smtp;

    public MailDispatcher(SmtpClient smtp) {
        this.smtp = smtp;
    }

    public void dispatch(Message message) {
~>        mailers.submit(() -> smtp.deliver(message));
    }
}
