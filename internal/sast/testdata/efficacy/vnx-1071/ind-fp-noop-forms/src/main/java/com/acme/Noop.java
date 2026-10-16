package com.acme;
import java.io.*;
import java.util.function.Runnable;
public class Noop implements Runnable {
    public void run() {}
    public Noop() {}
    void hook() { }
    Runnable r = () -> {};
    int[] a = {};
    int[][] b = new int[][] {};
    void spin(java.util.concurrent.atomic.AtomicBoolean f) {
        while (!f.get());
        try (InputStream in = new FileInputStream("x")) {
            in.read();
        } catch (IOException e) {}
    }
}
