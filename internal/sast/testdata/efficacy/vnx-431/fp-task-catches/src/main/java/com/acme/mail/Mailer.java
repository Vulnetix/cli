package com.acme.mail;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Mailer {
    private final ExecutorService workers = Executors.newCachedThreadPool();
    private final SmtpClient smtp;
    private final FormService service;

    public Mailer(SmtpClient smtp, FormService service) {
        this.smtp = smtp;
        this.service = service;
    }

    public void send(Message m) {
        workers.submit(() -> {
            try {
                smtp.deliver(m);
            } catch (Exception e) {
                Metrics.failed(e);
            }
        });
        service.submit(m.form());
    }
}
