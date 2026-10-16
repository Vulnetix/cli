package org.example.io;

public class Channel {
    private Session session;

    public void close() throws Throwable {
        if (session != null) {
            session
~>                .finalize();
        }
~>        finalize();
    }

    public void abort(Session s) throws Throwable {
~>        s.finalize ( );
    }
}
