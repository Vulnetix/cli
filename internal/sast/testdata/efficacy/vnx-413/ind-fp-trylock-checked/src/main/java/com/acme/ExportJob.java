package com.acme;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

public class ExportJob {
    private final ReentrantLock exportLock = new ReentrantLock();

    public boolean runNightly(Exporter exporter) throws InterruptedException {
        if (exportLock.tryLock(5, TimeUnit.SECONDS)) {
            try {
                exporter.exportAll();
                return true;
            } finally {
                exportLock.unlock();
            }
        }
        return false;
    }

    public boolean runNow(Exporter exporter) {
        boolean acquired = exportLock.tryLock();
        if (!acquired) {
            return false;
        }
        try {
            exporter.exportAll();
        } finally {
            exportLock.unlock();
        }
        return true;
    }
}
