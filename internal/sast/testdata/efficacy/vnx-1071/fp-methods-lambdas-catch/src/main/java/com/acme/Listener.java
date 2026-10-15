package com.acme;

public class Listener implements Runnable {
    public Listener() {}

    @Override
    public void run() {
    }

    public void onEvent(String e) {}

    public Runnable noop() {
        return () -> {};
    }

    public void parse(String s) {
        try {
            Integer.parseInt(s);
        } catch (NumberFormatException e) {
        }
        new Thread(() -> {
        }).start();
        String[] empty = new String[] {};
    }
}
