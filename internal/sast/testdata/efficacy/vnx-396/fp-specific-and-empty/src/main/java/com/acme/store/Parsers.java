package com.acme.store;

public class Parsers {
    public int parse(String s) {
        try {
            return Integer.parseInt(s);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    public void quiet(Runnable r) {
        try {
            r.run();
        } catch (Exception e) {
        }
    }

    public void ignore(Runnable r) {
        try {
            r.run();
        } catch (Exception ignored) {
            fallbacks++;
        }
    }

    class MyException extends Exception {}
}
