package com.example.sched;

import java.util.TimerTask;
import java.util.concurrent.ExecutorService;

public class Ticker {
    private final ExecutorService pool;
    private final Runnable onTick;

    public Ticker(ExecutorService pool, Runnable onTick) {
        this.pool = pool;
        this.onTick = onTick;
    }

    public void tickNow() {
        onTick.run();
        TimerTask task = new TimerTask() {
            @Override
            public void run() {
                onTick.run();
            }
        };
        task.run();
        pool.submit(onTick);
        Thread t = new Thread(onTick, "tick");
        t.start();
        Runnable r = () -> System.out.println("thread.run() would be wrong");
        r.run();
    }
}
