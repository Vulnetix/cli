package com.example;

public class Notes {
    // lock.lock(); work(); lock.unlock(); leaks the lock on exception
    static final String HINT = "in = new FileInputStream(f); in.close();";
}
