package com.acme;
import javax.xml.XMLConstants;
import javax.xml.parsers.*;
public class Sax {
    SAXParser make() throws Exception {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        return spf.newSAXParser();
    }
}
