package com.acme.jobs;

public class NightlyImport {
    private volatile boolean lastRunFailed;
    private final Importer importer;

    public NightlyImport(Importer importer) {
        this.importer = importer;
    }

    public boolean runOnce() {
        try {
            importer.importAll();
            lastRunFailed = false;
            return true;
~>        } catch (final Throwable t) {
            lastRunFailed = true;
            return false;
        }
    }

    public int pendingCount() {
        try {
            return importer.pending();
~>        } catch (java.lang.RuntimeException ex) {
            return -1;
        }
    }
}
