package com.acme.xml;

import java.io.InputStream;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import @@sample:o[r]g[.][w]3c[.]do[m][.]D[o]cu[m]en[t]@@;

public final class XmlSupport {
    private static final DocumentBuilderFactory SAFE_FACTORY =
            DocumentBuilderFactory.newInstance();

    static {
        try {
            SAFE_FACTORY.setFeature(
                    "http://apache.org/xml/features/disallow-doctype-decl", true);
        } catch (ParserConfigurationException e) {
            throw new IllegalStateException(e);
        }
    }

    private XmlSupport() {}

    public static Document parse(InputStream in) throws Exception {
        javax.xml.parsers.DocumentBuilderFactory local =
                javax.xml.parsers.DocumentBuilderFactory.newInstance();
        local.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        return local.newDocumentBuilder().parse(in);
    }
}
