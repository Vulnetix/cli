package com.acme.xml;

import java.io.InputStream;
import javax.xml.parsers.SAXParserFactory;
import org.xml.sax.helpers.DefaultHandler;

public class InvoiceXml {
    private static final String DISALLOW_DOCTYPE =
            "http://apache.org/xml/features/disallow-doctype-decl";

    public void parse(InputStream in, DefaultHandler handler) throws Exception {
        SAXParserFactory saxFactory = SAXParserFactory.newInstance();
        saxFactory.setFeature(
                DISALLOW_DOCTYPE,
                true);
        saxFactory.newSAXParser().parse(in, handler);
    }

    public void parseStrict(InputStream in, DefaultHandler handler) throws Exception {
        SAXParserFactory strict = SAXParserFactory.newInstance();
        strict.setFeature(
                "http://xml.org/sax/features/external-general-entities",
                false);
        strict.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        strict.newSAXParser().parse(in, handler);
    }
}
