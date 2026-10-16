package com.acme.ser;

import java.io.InputStream;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;

public class Filtered {
    public Object read(InputStream raw) throws Exception {
        ObjectInputStream in = new ObjectInputStream(raw);
        in.setObjectInputFilter(ObjectInputFilter.Config.createFilter("com.acme.model.*;!*"));
        return in.readObject();
    }
}
