package org.acme;

public class Scan {
    int count(int[] xs) {
        int n = 0;
        for (int x : xs)
            if (x > 0)
                n++;
        return n;
    }

    void log(boolean debug) {
        if (debug)
            System.out.println("debug");
        else
            System.out.println("quiet");
        done();
    }
}
