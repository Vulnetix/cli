package com.acme.feed;

import java.io.InputStream;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import @@sample:o[r]g[.][w]3c[.]do[m][.]D[o]cu[m]en[t]@@;

public class SafeFeedReader {
    public Document read(InputStream in) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature(
            "http://apache.org/xml/features/disallow-doctype-decl",
            true);
        return dbf.newDocumentBuilder().parse(in);
    }

    public Document readSecure(InputStream in) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, Boolean.TRUE);
        return factory.newDocumentBuilder().parse(in);
    }
}
