package com.acme.billing;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.ejb.Stateless;

@Stateless
public class InvoiceService {

    private final ExecutorService pool =
~>            Executors.newFixedThreadPool(4);

    public void render(Invoice inv) {
~>        Thread t = new Thread(() -> pdf(inv));
        t.start();
~>        new Thread (this::audit).start();
    }
}
