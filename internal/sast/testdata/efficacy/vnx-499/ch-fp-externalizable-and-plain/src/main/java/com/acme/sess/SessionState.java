package com.acme.sess;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

public class SessionState implements Externalizable {
    private String sessionToken;

    public void writeExternal(ObjectOutput out) throws IOException {
        out.writeUTF("redacted");
    }

    public void readExternal(ObjectInput in) throws IOException {
        in.readUTF();
    }
}

class PlainHolder {
    private String password;
}
