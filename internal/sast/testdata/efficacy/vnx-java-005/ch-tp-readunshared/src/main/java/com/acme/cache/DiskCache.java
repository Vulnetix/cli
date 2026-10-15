package com.acme.cache;

import java.io.FileInputStream;
import java.io.ObjectInputStream;

public class DiskCache {
    public Object load(String file) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(file))) {
~>            return ois.readUnshared();
        }
    }
}
