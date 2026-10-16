package com.acme.jobs;

public class Batch {
    private final StringBuilder log = new StringBuilder();

    @Override
    protected void finalize() throws Throwable {
        try {
            log.setLength(0);
        } finally {
            super.finalize();
        }
    }

    public void finalize(int exitCode) {
        log.append("exit=").append(exitCode);
    }

    public void finalizeOrder() {
        log.append("finalized");
    }

    public static void finalizeBatch(Batch b) {
        b.finalizeOrder();
    }
}
