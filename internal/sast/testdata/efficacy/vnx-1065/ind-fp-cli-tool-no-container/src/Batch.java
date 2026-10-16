package tools;

import java.util.concurrent.Executors;

public class Batch {
    public void run() {
        Executors.newFixedThreadPool(8);
        new Thread(() -> {}).start();
        System.exit(0);
    }
}
