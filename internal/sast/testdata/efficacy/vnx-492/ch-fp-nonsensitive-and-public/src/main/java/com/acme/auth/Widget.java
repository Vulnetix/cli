package com.acme.auth;

public class Widget {
    private String title;
    public String token;

    class Renderer {
        String draw() { return title + token; }
    }

    Runnable r = new Runnable() {
        public void run() { System.out.println(title); }
    };
}
