package com.acme;
import javax.xml.parsers.*;
public class Hard {
    DocumentBuilder make() throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        return dbf.newDocumentBuilder();
    }
}
