package com.acme.auth;

public class Tokens {
    boolean differs(String expected, String actual) {
~>        if (expected != actual) {
            return true;
        }
        return false;
    }
}
