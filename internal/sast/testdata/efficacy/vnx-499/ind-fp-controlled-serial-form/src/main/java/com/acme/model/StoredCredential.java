package com.acme.model;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;

public class StoredCredential implements Serializable {
    private String username;
    private String password;

    private void writeObject(ObjectOutputStream out) throws IOException {
        out.writeUTF(username);
    }
}
