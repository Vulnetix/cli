package com.example.xml;

import org.xml.sax.XMLReader;
import javax.xml.parsers.SAXParserFactory;

public class FeedParser {
    public XMLReader reader() throws Exception {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        XMLReader reader = spf.newSAXParser().getXMLReader();
~>        reader.setFeature("http://xml.org/sax/features/external-general-entities", true);
~>        reader.setFeature("http://xml.org/sax/features/external-parameter-entities", true);
~>        spf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", true);
        return reader;
    }
}
