package com.acme.xml;

import java.io.InputStream;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import org.xml.sax.InputSource;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.DefaultHandler;
import org.xml.sax.helpers.XMLReaderFactory;

public class FeedReader {
    public void read(InputStream in, DefaultHandler handler) throws Exception {
~>        SAXParserFactory spf = SAXParserFactory.newInstance();
        SAXParser parser = spf.newSAXParser();
        parser.parse(in, handler);
    }

    public void readLegacy(InputStream in, DefaultHandler handler) throws Exception {
~>        XMLReader reader = XMLReaderFactory.createXMLReader();
        reader.setContentHandler(handler);
        reader.parse(new InputSource(in));
    }
}
