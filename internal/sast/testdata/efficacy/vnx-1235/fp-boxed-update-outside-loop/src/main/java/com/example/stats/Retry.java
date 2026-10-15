package com.example.stats;

public class Retry {
    Integer attempts(Runnable r) {
        Integer retries = 3;
        retries++;
        Integer done = 0;
        for (int i = 0; i < 3; i++) {
            r.run();
        }
        done += 1;
        return retries + done;
    }
}
