package com.acme.io;

import java.io.InputStream;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;

public class FilteredRestore {
    public Object restore(InputStream body) throws Exception {
        ObjectInputStream in = new ObjectInputStream(body);
        in.setObjectInputFilter(ObjectInputFilter.Config.createFilter("com.acme.model.*;!*"));
        return in.readObject();
    }
}
