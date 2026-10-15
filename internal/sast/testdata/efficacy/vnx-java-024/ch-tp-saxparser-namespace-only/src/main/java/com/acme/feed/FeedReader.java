package com.acme.feed;

import java.io.InputStream;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import org.xml.sax.helpers.DefaultHandler;

public class FeedReader {
    public void read(InputStream in, DefaultHandler handler) throws Exception {
~>        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setNamespaceAware(true);
        spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        SAXParser parser = spf.newSAXParser();
        parser.parse(in, handler);
    }
}
