package com.acme.xml;

import java.io.InputStream;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import @@sample:o[r]g[.][w]3c[.]do[m][.]D[o]cu[m]en[t]@@;

public class TolerantParser {
    private static final org.slf4j.Logger LOG = @@sample:o[r]g[.][s]lf[4]j[.][L]og[g]er[F]ac[t]or[y][.]g[e]tL[o]gg[e]r@@(TolerantParser.class);

    public Document parse(InputStream in) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        try {
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        } catch (ParserConfigurationException e) {
            LOG.warn("parser does not support hardening features", e);
        }
        return dbf.newDocumentBuilder().parse(in);
    }
}
