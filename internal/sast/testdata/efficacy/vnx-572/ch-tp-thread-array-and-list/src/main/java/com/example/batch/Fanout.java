package com.example.batch;

import java.util.ArrayList;
import java.util.List;

public class Fanout {
    public void runAll(List<Runnable> tasks) {
        Thread[] workers = new Thread[tasks.size()];
        for (int i = 0; i < workers.length; i++) {
            workers[i] = new Thread(tasks.get(i));
~>            workers[i].run();
        }
        List<Thread> extra = new ArrayList<>();
        for (Runnable r : tasks) {
            extra.add(new Thread(r));
        }
        for (Thread t : extra) {
~>            t.run();
        }
    }
}
