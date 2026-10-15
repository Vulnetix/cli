package com.acme.web;

import javax.annotation.Resource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class Greeter {
    @Value("${greeting.prefix}")
    private String prefix;

    @Resource
    private MessageSource messages;

    public String greet(String name) {
        return prefix.trim() + messages.lookup(name);
    }
}
