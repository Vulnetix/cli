package com.acme.io;

import java.beans.XMLDecoder;
import java.io.InputStream;

public class BeanImporter {
    public Object load(InputStream upload) {
~>        try (XMLDecoder decoder = new XMLDecoder(upload)) {
            return decoder.readObject();
        }
    }
}
