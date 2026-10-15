package com.acme.web;

import javax.ejb.Stateless;

@Stateless
public class ReportBean {
    public void generate(final String id) {
~>        Thread worker = new Thread(() -> render(id));
        worker.start();
~>        new Thread(this::cleanup, "cleanup").start();
    }

    private void render(String id) {}
    private void cleanup() {}
}
