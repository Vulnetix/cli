package com.acme;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@javax.ejb.Stateless
public class Batch {
    public void run(Runnable r) {
~>        ExecutorService ex = Executors.newFixedThreadPool(4);
        ex.submit(r);
    }
}
