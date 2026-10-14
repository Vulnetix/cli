package com.example.xml;

import java.io.InputStream;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.SAXParserFactory;
import org.dom4j.io.SAXReader;
import org.w3c.dom.Document;

public class SafeParser {
    private static final String DISALLOW_DOCTYPE = "http://apache.org/xml/features/disallow-doctype-decl";

    public Document dom(InputStream in) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        return dbf.newDocumentBuilder().parse(in);
    }

    public void sax(InputStream in) throws Exception {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setFeature(DISALLOW_DOCTYPE, true);
        spf.newSAXParser().parse(in, new org.xml.sax.helpers.DefaultHandler());
    }

    public Object dom4j(InputStream in) throws Exception {
        SAXReader reader = new SAXReader();
        reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        return reader.read(in);
    }
}
