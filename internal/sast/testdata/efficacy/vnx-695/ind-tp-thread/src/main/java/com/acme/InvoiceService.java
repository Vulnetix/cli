package com.acme;

import javax.ejb.Stateless;

@Stateless
public class InvoiceService {
    public void render(Invoice inv) {
~>        Thread t = new Thread(() -> pdf(inv));
        t.start();
    }
}
