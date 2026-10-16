package com.acme.jobs;

public class FixedGreeter implements Greeter {
    @Override
    public String greet(String who) {
        return "hello";
    }
}
