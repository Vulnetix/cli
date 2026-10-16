package com.acme.ops;

public class EchoGreeter implements Greeter {
    @Override
    public String greet(String who) {
        String text = who;
        return text;
    }
}
