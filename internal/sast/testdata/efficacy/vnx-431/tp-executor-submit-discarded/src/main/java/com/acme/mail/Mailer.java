package com.acme.mail;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Mailer {
    private final ExecutorService workers = Executors.newFixedThreadPool(4);
    private final SmtpClient smtp;

    public Mailer(SmtpClient smtp) {
        this.smtp = smtp;
    }

    public void send(Message m) {
~>        workers.submit(() -> smtp.deliver(m));
    }

    public void sendAll(Iterable<Message> batch) {
        for (Message m : batch) {
~>            this.workers.submit(() -> {
                smtp.connect();
                smtp.deliver(m);
            });
        }
    }
}
