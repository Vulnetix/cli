package com.acme.io;

import java.util.concurrent.ExecutorService;

public class Writer {
    private ExecutorService executor;

    int write(byte[] b) {
        int n = 0;
        try {
            n = out(b);
            return n;
        } finally {
            flush();
            executor.submit(() -> {
                return drain();
            });
            executor.execute(new Runnable() {
                @Override
                public void run() {
                    return;
                }
            });
        }
    }

    int after() {
        try {
            out(new byte[0]);
        } finally {
            flush();
        }
        return 0;
    }
}
