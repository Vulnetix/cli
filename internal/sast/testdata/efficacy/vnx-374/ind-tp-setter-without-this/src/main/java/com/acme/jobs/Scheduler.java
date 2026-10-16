package com.acme.jobs;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashSet;
import java.net.InetAddress;

public class Scheduler {
    private Deque<Job> queue = new ArrayDeque<>();
    private HashSet<InetAddress> allowedCallers = new HashSet<>();

    public synchronized void replaceQueue(Deque<Job> jobs) {
        if (jobs == null) {
            throw new IllegalArgumentException("jobs");
        }
~>        queue = jobs;
    }

    public void setAllowedCallers(HashSet<InetAddress> callers) {
~>        this.allowedCallers = callers;
    }

    public boolean accepts(InetAddress caller) {
        return allowedCallers.contains(caller);
    }
}
