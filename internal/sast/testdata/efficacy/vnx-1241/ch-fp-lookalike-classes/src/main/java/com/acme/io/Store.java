package com.acme.io;

import java.io.RandomAccessFile;

public class Store {
    private final Generator generator = new Generator();

    public RandomAccessFile open(String p) throws Exception {
        RandomAccessFile f = new RandomAccessFile(p, "rw");
        generator.setSeed(42);
        new RandomWalk(7).run();
        return f;
    }

    static class Generator {
        void setSeed(long s) {}
    }

    static class RandomWalk {
        RandomWalk(int n) {}
        void run() {}
    }
}
