package com.example.boot;

import jakarta.annotation.PostConstruct;
import jakarta.ejb.Singleton;
import jakarta.ejb.Startup;

@Singleton
@Startup
public class Startup {
    @PostConstruct
    void init() throws Exception {
~>        ClassLoader sys = ClassLoader.getSystemClassLoader();
        sys.loadClass("com.example.boot.Warmup");
    }
}
