package com.acme.xml;

import java.io.InputStream;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import @@sample:o[r]g[.][w]3c[.]do[m][.]D[o]cu[m]en[t]@@;

public final class SafeXml {
    private static final DocumentBuilderFactory DBF = DocumentBuilderFactory.newInstance();

    static {
        try {
            DBF.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            DBF.setXIncludeAware(false);
        } catch (ParserConfigurationException e) {
            throw new IllegalStateException(e);
        }
    }

    public static Document parse(InputStream in) throws Exception {
        return DBF.newDocumentBuilder().parse(in);
    }

    public static Document parseLenient(InputStream in) throws Exception {
        DocumentBuilderFactory lenient = DocumentBuilderFactory.newInstance();
        lenient.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        lenient.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        return lenient.newDocumentBuilder().parse(in);
    }
}
