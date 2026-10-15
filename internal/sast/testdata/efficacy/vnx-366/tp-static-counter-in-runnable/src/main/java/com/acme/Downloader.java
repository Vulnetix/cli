package com.acme;

public class Downloader implements Runnable {
    private static int completed = 0;
    static long bytesTotal;

    @Override
    public void run() {
        long n = fetch();
~>        bytesTotal += n;
~>        completed++;
    }

    private long fetch() {
        return 42L;
    }

    public static void main(String[] args) {
        for (int i = 0; i < 4; i++) {
            new Thread(new Downloader()).start();
        }
    }
}
