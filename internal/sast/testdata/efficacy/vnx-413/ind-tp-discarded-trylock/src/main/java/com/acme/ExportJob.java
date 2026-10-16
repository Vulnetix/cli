package com.acme;

import java.util.concurrent.locks.ReentrantLock;

public class ExportJob {
    private final ReentrantLock exportLock = new ReentrantLock();
    private final Exporter exporter;

    public ExportJob(Exporter exporter) {
        this.exporter = exporter;
    }

    public void runNightly() {
~>        exportLock.tryLock();
        try {
            exporter.exportAll();
        } finally {
            exportLock.unlock();
        }
    }
}
