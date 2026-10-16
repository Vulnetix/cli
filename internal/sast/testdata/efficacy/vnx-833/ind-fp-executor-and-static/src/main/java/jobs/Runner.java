package jobs;

import java.util.concurrent.ExecutorService;

public class Runner {
    private final Object a = new Object();
    private final Object b = new Object();
    private ExecutorService executor;

    void first() {
        synchronized (a) {
            executor.submit(() -> {
                synchronized (b) {
                    touch();
                }
            });
        }
    }

    void second() {
        synchronized (b) {
            new Thread(() -> {
                synchronized (a) {
                    touch();
                }
            }).start();
        }
    }

    static synchronized void util() {
        log();
    }
}
