package com.acme.jobs;

import java.util.concurrent.Callable;

public class ExportTask implements Callable<Integer>, AutoCloseable {
    private final Exporter exporter;

    public ExportTask(Exporter exporter) {
        this.exporter = exporter;
    }

    public static void main(String[] args) throws Exception {
        new ExportTask(new Exporter()).call();
    }

    @Override
    public Integer call() throws Exception {
        return exporter.exportAll();
    }

    @Override
    public void close() throws Exception {
        exporter.shutdown();
    }
}
