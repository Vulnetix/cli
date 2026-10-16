package com.acme.ser;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.Serializable;
import org.apache.commons.io.serialization.ValidatingObjectInputStream;

public class Val implements Serializable {
    private String name;

    public Object read(InputStream in) throws Exception {
        ValidatingObjectInputStream vois = new ValidatingObjectInputStream(in);
        vois.accept(Val.class);
        return vois.readObject();
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        if (name == null) throw new IOException("bad");
    }
}
