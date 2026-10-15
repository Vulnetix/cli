package com.example.work;

public class Parser {
    public Object parse(String s) {
        try {
            return deepParse(s, 0);
~>        } catch (StackOverflowError e) {
            return null;
        }
    }

    public void loadNative() {
        try {
            System.loadLibrary("fast");
        } catch (UnsatisfiedLinkError err) {
            System.err.println("native lib missing");
        }
    }

    private Object deepParse(String s, int d) { return s; }
}
