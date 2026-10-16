package com.acme.feed;

import java.io.InputStream;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import org.xml.sax.InputSource;
import org.xml.sax.XMLReader;

public class FeedParser {

    public void parse(InputStream body, FeedHandler handler) throws Exception {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setNamespaceAware(true);
        SAXParser parser = spf.newSAXParser();
        XMLReader reader = parser.getXMLReader();
~>        reader.setFeature("http://xml.org/sax/features/external-general-entities", true);
~>        parser.getXMLReader().setFeature(
                "http://xml.org/sax/features/external-parameter-entities", true);
~>        reader.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", true);
        reader.setContentHandler(handler);
        reader.parse(new InputSource(body));
    }
}
