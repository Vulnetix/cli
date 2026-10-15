package com.acme.xml;

import java.io.InputStream;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import org.xml.sax.helpers.DefaultHandler;

public class SoapHandler {
    public void handle(InputStream body, DefaultHandler handler) throws Exception {
~>        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setNamespaceAware(true);
        spf.setValidating(false);
        SAXParser parser = spf.newSAXParser();
        parser.parse(body, handler);
    }
}
