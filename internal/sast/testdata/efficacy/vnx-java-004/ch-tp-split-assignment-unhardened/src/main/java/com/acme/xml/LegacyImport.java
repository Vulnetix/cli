package com.acme.xml;

import java.io.InputStream;
import @@sample:o[r]g[.][w]3c[.]do[m][.]D[o]cu[m]en[t]@@;

public class LegacyImport {
    public Document parse(InputStream upload) throws Exception {
        javax.xml.parsers.DocumentBuilderFactory builderFactory =
~>                javax.xml.parsers.DocumentBuilderFactory.newInstance();
        builderFactory.setNamespaceAware(true);
        return builderFactory.newDocumentBuilder().parse(upload);
    }
}
