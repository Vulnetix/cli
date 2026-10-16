package com.acme.xml;

import java.io.InputStream;
import javax.xml.parsers.*;
import org.xml.sax.helpers.DefaultHandler;

public class FeedParser {
    public void parse(InputStream in, DefaultHandler h) throws Exception {
~>        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setNamespaceAware(true);
        SAXParser p = spf.newSAXParser();
        p.parse(in, h);
    }
}
