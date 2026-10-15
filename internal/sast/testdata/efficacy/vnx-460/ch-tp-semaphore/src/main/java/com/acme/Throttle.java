package com.acme;

import java.util.concurrent.Semaphore;

public class Throttle {
    private final Semaphore permits = new Semaphore(4);

    public String call(Backend backend, String req) throws InterruptedException {
~>        permits.acquire();
        String res = backend.send(req);
        permits.release();
        return res;
    }
}
