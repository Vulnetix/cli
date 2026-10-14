package com.acme.io;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.Serializable;
import org.apache.commons.io.serialization.ValidatingObjectInputStream;

public class Task implements Serializable {
    private String name;

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        name = (String) in.readObject();
    }

    public static Object load(InputStream body) throws Exception {
        ValidatingObjectInputStream vin = new ValidatingObjectInputStream(body);
        vin.accept(Task.class);
        return vin.readObject();
    }
}
