package com.acme.ser;

import java.io.*;

public class Copier {
    @SuppressWarnings("unchecked")
    public static <T extends Serializable> T copy(T obj) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(obj);
        oos.flush();
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bos.toByteArray()));
        return (T) ois.readObject();
    }
}
