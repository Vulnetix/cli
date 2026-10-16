package com.acme;

import java.util.ArrayList;
import java.util.List;

public class Collector implements Runnable {
~>    static List<String> seen = new ArrayList<>();

    public void run() {
        seen.add(Thread.currentThread().getName());
    }
}
