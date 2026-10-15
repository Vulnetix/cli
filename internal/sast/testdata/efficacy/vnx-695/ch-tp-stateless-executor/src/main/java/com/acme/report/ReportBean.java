package com.acme.report;

import javax.ejb.Stateless;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Stateless
public class ReportBean {

    public void generate(final String id) {
~>        Thread worker = new Thread(() -> render(id));
        worker.start();
    }

    private void render(String id) {
    }
}
