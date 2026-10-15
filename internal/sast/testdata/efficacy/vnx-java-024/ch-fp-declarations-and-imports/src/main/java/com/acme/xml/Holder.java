package com.acme.xml;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.SAXParserFactory;

public class Holder {
    private DocumentBuilderFactory factory;
    private SAXParserFactory saxFactory;

    // DocumentBuilderFactory.newInstance() must be hardened before use.
    public Holder(DocumentBuilderFactory factory, SAXParserFactory saxFactory) {
        this.factory = factory;
        this.saxFactory = saxFactory;
        String doc = "DocumentBuilderFactory.newInstance() is unsafe by default";
    }
}
