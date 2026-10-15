package com.acme.xml;

import java.io.InputStream;
import javax.xml.parsers.DocumentBuilderFactory;
import @@sample:o[r]g[.][w]3c[.]do[m][.]D[o]cu[m]en[t]@@;

public final class XmlUtils {
    private XmlUtils() {
    }

    public static Document parseTrusted(InputStream in) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        return dbf.newDocumentBuilder().parse(in);
    }

    public static Document parseUpload(InputStream in) throws Exception {
~>        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        return dbf.newDocumentBuilder().parse(in);
    }
}
