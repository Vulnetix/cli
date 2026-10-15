package com.example;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ReportJob {
    public static void main(String[] args) throws Exception {
        ExecutorService writer = Executors.newFixedThreadPool(1);
        writer.submit(() -> writeReport(args[0]));
        writer.shutdown();
    }
}
