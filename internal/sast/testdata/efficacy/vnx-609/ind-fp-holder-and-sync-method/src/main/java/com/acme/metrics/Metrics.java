package com.acme.metrics;

import java.util.concurrent.atomic.AtomicReference;

public final class Metrics {

    private Reporter reporter;
    private final AtomicReference<Exporter> exporter = new AtomicReference<>();

    private Metrics() {
    }

    private static final class Holder {
        static final Metrics INSTANCE = new Metrics();
    }

    public static Metrics get() {
        return Holder.INSTANCE;
    }

    public synchronized Reporter reporter() {
        if (reporter == null) {
            reporter = new Reporter();
        }
        return reporter;
    }

    public Exporter exporter() {
        if (exporter.get() == null) {
            synchronized (exporter) {
                if (exporter.get() == null) {
                    exporter.set(new Exporter());
                }
            }
        }
        return exporter.get();
    }

    public void flush() {
        synchronized (this) {
            if (reporter == null) {
                return;
            }
            reporter.flush();
        }
    }
}
