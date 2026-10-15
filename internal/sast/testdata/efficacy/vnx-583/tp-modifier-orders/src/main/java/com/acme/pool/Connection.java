package com.acme.pool;

public class Connection {
~>    public synchronized void finalize() {
        close();
    }

    void close() {}
}

class Cursor {
~>    final public void finalize ( ) throws Throwable { }
}

class Lease {
~>    @Override public void finalize()
        throws Throwable {
        super.finalize();
    }
}
