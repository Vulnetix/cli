package com.acme.xml;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.SAXParserFactory;
import @@sample:o[r]g[.][w]3c[.]do[m][.]D[o]cu[m]en[t]@@;

public class InvoiceParser {
    private static final String DISALLOW_DOCTYPE = "http://apache.org/xml/features/disallow-doctype-decl";

    public Document parse(java.io.InputStream in) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
~>        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
~>        dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        return db.parse(in);
    }

    public SAXParserFactory legacyFactory() throws Exception {
        SAXParserFactory spf = SAXParserFactory.newInstance();
~>        spf.setFeature(DISALLOW_DOCTYPE, false);
~>        spf.setFeature(
            "http://apache.org/xml/features/disallow-doctype-decl",
            false);
        return spf;
    }
}
