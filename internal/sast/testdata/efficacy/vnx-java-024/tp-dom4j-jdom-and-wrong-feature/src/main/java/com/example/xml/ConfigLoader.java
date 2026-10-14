package com.example.xml;

import java.io.InputStream;
import javax.xml.parsers.DocumentBuilderFactory;
import org.dom4j.io.SAXReader;
import org.jdom2.input.SAXBuilder;

public class ConfigLoader {
    private static final DocumentBuilderFactory SAFE = DocumentBuilderFactory.newInstance();

    static {
        try {
            SAFE.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public Object dom4j(InputStream in) throws Exception {
~>        SAXReader reader = new SAXReader();
        return reader.read(in);
    }

    public Object jdom(InputStream in) throws Exception {
~>        SAXBuilder builder = new SAXBuilder();
        return builder.build(in);
    }

    public Object other(InputStream in) throws Exception {
~>        DocumentBuilderFactory unsafe = DocumentBuilderFactory.newInstance();
        unsafe.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
        return unsafe.newDocumentBuilder().parse(in);
    }
}
