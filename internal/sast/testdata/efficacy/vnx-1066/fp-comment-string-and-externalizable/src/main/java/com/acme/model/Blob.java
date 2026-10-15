package com.acme.model;

import java.io.Externalizable;

// class Old implements Serializable { } was replaced by Externalizable
public class Blob implements Externalizable {
    static final String DOC = "class X implements Serializable {";

    public void writeExternal(java.io.ObjectOutput out) {}
    public void readExternal(java.io.ObjectInput in) {}
}

class SerializableHelper implements Runnable {
    public void run() {}
}
