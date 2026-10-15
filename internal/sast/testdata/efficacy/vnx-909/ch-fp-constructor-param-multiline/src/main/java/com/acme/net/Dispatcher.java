package com.acme.net;

import java.util.concurrent.ExecutorService;

public class Dispatcher {
    private ExecutorService pool;
    private String name;

    public Dispatcher(String name,
                      ExecutorService pool) {
        this.name = name;
        this.pool =
            pool;
    }

    public void submit(Runnable r) {
        pool.submit(r);
        System.out.println(name.length());
    }
}
