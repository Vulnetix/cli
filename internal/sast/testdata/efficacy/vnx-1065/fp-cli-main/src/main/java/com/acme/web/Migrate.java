package com.acme.web;

public final class Migrate {
    public static void main(String[] args) {
        if (args.length == 0) {
            System.err.println("usage: migrate <dir>");
            System.exit(2);
        }
        new Thread(() -> run(args[0])).start();
    }

    private static void run(String dir) {}
}
