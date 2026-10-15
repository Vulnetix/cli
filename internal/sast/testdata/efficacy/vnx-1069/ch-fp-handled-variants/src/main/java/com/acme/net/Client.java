package com.acme.net;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Client {
    private static final Logger LOG = Logger.getLogger(Client.class.getName());

    public byte[] fetch(Connection c) {
        try { return c.read(); } catch (IOException e) { LOG.log(Level.WARNING, "read failed", e); }
        try {
            c.close();
        } catch (IOException closeFailure) {

            throw new IllegalStateException(closeFailure);
        }
        try { c.flush(); } catch (IOException ignoredOnShutdown) {}
        return new byte[0];
    }
}
