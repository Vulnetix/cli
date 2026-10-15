package com.acme;

import java.io.Serializable;
import java.util.logging.Logger;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Invoice implements Serializable {
    private static final Logger LOG = Logger.getLogger("invoice");
    private static final ExecutorService POOL = Executors.newCachedThreadPool();
    private long amount;
}
