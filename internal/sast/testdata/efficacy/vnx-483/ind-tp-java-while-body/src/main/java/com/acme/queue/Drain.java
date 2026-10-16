package com.acme.queue;

import java.util.Queue;

public class Drain {
    public int drain(Queue<Job> q) {
        int n = 0;
        while (!q.isEmpty())
            q.poll().run();
~>            n++;
        return n;
    }
}
