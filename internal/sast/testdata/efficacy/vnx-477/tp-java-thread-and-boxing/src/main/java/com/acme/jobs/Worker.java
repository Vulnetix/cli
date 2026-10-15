package com.acme.jobs;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;

public class Worker {
    private Thread workerThread;

    void cancel() {
~>        workerThread.stop();
~>        Thread.currentThread().suspend();
    }

    Integer boxed(int v) {
~>        Integer count = new Integer(v);
~>        Boolean flag = new Boolean("true");
        return count;
    }

    String header(InputStream raw) throws IOException {
        DataInputStream in = new DataInputStream(raw);
~>        return in.readLine();
    }

    @Override
~>    protected void finalize() {
        cancel();
    }

    static {
~>        System.runFinalizersOnExit(true);
    }
}
