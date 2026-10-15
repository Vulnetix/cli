package com.acme.model;

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.io.Serializable;

public class Vault implements Serializable {
    private String secret;

    private void writeObject(ObjectOutputStream out) throws IOException {
        throw new NotSerializableException("Vault");
    }
}
