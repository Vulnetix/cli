package com.acme.io;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import org.apache.commons.lang3.SerializationUtils;

public class Copier {
    public static <T extends Serializable> T copy(T value) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream out = new ObjectOutputStream(bos)) {
            out.writeObject(value);
        }
        ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bos.toByteArray()));
        @SuppressWarnings("unchecked")
        T copy = (T) in.readObject();
        return copy;
    }

    public static <T extends Serializable> T clone2(T value) {
        return SerializationUtils.deserialize(SerializationUtils.serialize(value));
    }
}
