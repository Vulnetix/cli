package com.acme.xml;

import java.io.InputStream;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

public class Safe {
    public Document read(InputStream in) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        return dbf.newDocumentBuilder().parse(in);
    }

    public javax.xml.stream.XMLInputFactory stax() {
        javax.xml.stream.XMLInputFactory f = javax.xml.stream.XMLInputFactory.newInstance();
        f.setProperty(javax.xml.stream.XMLInputFactory.SUPPORT_DTD, false);
        return f;
    }
}
