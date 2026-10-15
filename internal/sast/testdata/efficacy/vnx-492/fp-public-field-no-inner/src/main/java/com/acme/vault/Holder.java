package com.acme.vault;

public class Holder {
    private String password;

    String get() {
        Runnable r = () -> System.out.println(password.length());
        return password;
    }
}
