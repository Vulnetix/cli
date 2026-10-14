package com.example.xml;

import java.io.InputStream;
import javax.xml.XMLConstants;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;
import org.xml.sax.helpers.DefaultHandler;

public class FeedReader {
    public void sax(InputStream in, DefaultHandler h) throws Exception {
~>        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        SAXParser parser = spf.newSAXParser();
        parser.parse(in, h);
    }

    public XMLStreamReader stax(InputStream in) throws Exception {
~>        var xif = XMLInputFactory.newInstance();
        xif.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        return xif.createXMLStreamReader(in);
    }

    public XMLStreamReader staxFactory(InputStream in) throws Exception {
~>        XMLInputFactory f = XMLInputFactory.newFactory();
        return f.createXMLStreamReader(in);
    }
}
