package com.acme.net;

import java.util.concurrent.ExecutorService;

public class Dispatcher {
~>    private ExecutorService pool;
    private int submitted;

    public void submit(Runnable r) {
        submitted++;
        this.pool.submit(r);
    }
}
