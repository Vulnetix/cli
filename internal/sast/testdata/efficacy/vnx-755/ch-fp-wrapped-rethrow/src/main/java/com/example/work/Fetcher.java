package com.example.work;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

public class Fetcher {
    public String get(Future<String> f) {
        try {
            return f.get();
        } catch (InterruptedException e) {
            throw new IllegalStateException("interrupted", e);
        } catch (ExecutionException e) {
            System.err.println("failed: " + e);
            return "";
        }
    }
}
