package com.example.jobs;

public class Cache {
    byte[] allocate(int n) {
        try {
            return new byte[n];
~>        } catch (OutOfMemoryError oom) {
            System.gc();
            return new byte[0];
        }
    }

    int depth(Node n) {
        try {
            return 1 + depth(n.next);
~>        } catch (StackOverflowError | java.lang.InternalError e) {
            return -1;
        }
    }

    static class Node { Node next; }
}
