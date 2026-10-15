package com.example.work;

public class Main {
    public static void main(String[] args) {
        try {
            new Server().serve();
        } catch (OutOfMemoryError e) {
            System.err.println("out of memory, exiting");
            System.exit(3);
        }
        try {
            new Server().drain();
        } catch (StackOverflowError e) {
            Runtime.getRuntime().halt(4);
        }
    }
}
