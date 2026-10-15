package com.acme.xml;

import javax.xml.XMLConstants;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.stream.XMLInputFactory;

public class ImportService {
    void configure() throws Exception {
        SAXParser parser = SAXParserFactory.newInstance().newSAXParser();
        parser.getXMLReader().setFeature(
                "http://xml.org/sax/features/external-parameter-entities", false);
        parser.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        XMLInputFactory xif = XMLInputFactory.newFactory();
        xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        xif.setProperty(XMLInputFactory.SUPPORT_DTD, Boolean.FALSE);
    }
}
