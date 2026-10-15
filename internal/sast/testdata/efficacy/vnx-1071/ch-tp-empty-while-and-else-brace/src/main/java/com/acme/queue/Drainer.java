package com.acme.queue;

public class Drainer {
    public void drain(Queue q, boolean verbose) {
~>        while (q.isBusy())
        {
        }
        if (verbose) {
            q.dump();
        }
~>        else
        {

        }
    }
}
