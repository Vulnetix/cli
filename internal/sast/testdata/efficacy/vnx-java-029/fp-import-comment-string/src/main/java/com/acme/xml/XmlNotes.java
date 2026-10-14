package com.acme.xml;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.SAXParserFactory;
import org.xml.sax.XMLReader;

public class XmlNotes {
    // DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    private static final String NOTE = "call DocumentBuilderFactory.newInstance() and harden it";
    private XMLReader reader;
    private DocumentBuilderFactory injected;

    public XmlNotes(DocumentBuilderFactory injected, XMLReader reader) {
        this.injected = injected;
        this.reader = reader;
    }

    public String describe() {
        return NOTE + SAXParserFactory.class.getName();
    }
}
