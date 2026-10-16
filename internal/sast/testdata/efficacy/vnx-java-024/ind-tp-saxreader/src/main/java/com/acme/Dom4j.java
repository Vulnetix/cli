package com.acme;
import org.dom4j.io.SAXReader;
public class Dom4j {
    Object read(java.io.File f) throws Exception {
~>        SAXReader reader = new SAXReader();
        reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
        return reader.read(f);
    }
}
