package com.acme.xml;

import java.io.InputStream;
import javax.xml.parsers.DocumentBuilderFactory;
import @@sample:o[r]g[.][w]3c[.]do[m][.]D[o]cu[m]en[t]@@;

public class DualParser {

    public Document[] parseBoth(InputStream trusted, InputStream upload) throws Exception {
~>        DocumentBuilderFactory uploadFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilderFactory trustedFactory = DocumentBuilderFactory.newInstance();
        trustedFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        Document a = trustedFactory.newDocumentBuilder().parse(trusted);
        Document b = uploadFactory.newDocumentBuilder().parse(upload);
        return new Document[] {a, b};
    }
}
