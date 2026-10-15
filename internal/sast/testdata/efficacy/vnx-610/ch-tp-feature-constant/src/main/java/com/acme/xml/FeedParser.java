package com.acme.xml;

import javax.xml.parsers.SAXParserFactory;

public class FeedParser {
    private static final String GENERAL_ENTITIES = "http://xml.org/sax/features/external-general-entities";
    private static final String DTD_LOADING =
            "http://apache.org/xml/features/nonvalidating/load-external-dtd";

    SAXParserFactory factory() throws Exception {
        SAXParserFactory spf = SAXParserFactory.newInstance();
~>        spf.setFeature(GENERAL_ENTITIES, true);
~>        spf.setFeature(DTD_LOADING, Boolean.TRUE);
        return spf;
    }
}
