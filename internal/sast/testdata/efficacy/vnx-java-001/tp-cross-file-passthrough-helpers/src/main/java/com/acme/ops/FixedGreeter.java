package com.acme.ops;

public class FixedGreeter implements Greeter {
    @Override
    public String greet(String who) {
        return "hello";
    }
}
