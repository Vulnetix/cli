package com.acme.io;

public class Pipe {
    public boolean ready(Object source, Channel sink) {
        if (source != null & sink.isOpen()) {
            return true;
        }
        boolean ok = source != null && source.hashCode() > 0;
        ok &= sink != null;
        return ok | source == null;
    }
}
