package com.acme;

import java.io.Serializable;
import java.sql.Connection;
import java.util.concurrent.ExecutorService;

public class ReportJob extends BaseJob
        implements Runnable, Serializable {

~>    private Connection connection;
~>    public ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(2);
    private int retries = 3;

    public void run() {
        Connection local = connection;
    }
}
