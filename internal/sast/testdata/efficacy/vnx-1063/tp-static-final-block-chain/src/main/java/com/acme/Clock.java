package com.acme;

public class Clock {
    private static Clock instance;
~>    static { instance = new Clock(); }

    static {
~>        Scheduler s = new Scheduler(); s.start();
    }
}
