package com.acme.xml;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.SAXParserFactory;
import org.xml.sax.XMLReader;

public class ValidatingParser {

    public XMLReader reader() throws Exception {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setFeature("http://xml.org/sax/features/namespaces", true);
        spf.setFeature("http://xml.org/sax/features/namespace-prefixes", true);
        spf.setFeature("http://apache.org/xml/features/validation/schema", true);
        spf.setValidating(true);
        return spf.newSAXParser().getXMLReader();
    }

    public DocumentBuilderFactory defaults() {
        // Left at defaults; hardening is judged by other rules.
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        dbf.setIgnoringComments(true);
        return dbf;
    }
}
