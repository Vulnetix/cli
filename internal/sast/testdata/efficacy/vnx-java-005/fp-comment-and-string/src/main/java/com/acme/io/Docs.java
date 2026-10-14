package com.acme.io;

public class Docs {
    // Never call new ObjectInputStream(request.getInputStream()).readObject() on request bodies.
    private static final String WARNING = "mapper.enableDefaultTyping() is unsafe; so is new XMLDecoder(in)";

    /*
     * xstream.fromXML(payload) needs an allowlist.
     */
    public String warning() {
        return WARNING;
    }
}
