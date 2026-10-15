package com.acme.xml;

import java.io.File;
import javax.xml.parsers.DocumentBuilderFactory;
import @@sample:o[r]g[.][w]3c[.]do[m][.]D[o]cu[m]en[t]@@;

public class ConfigLoader {

    public Document load(File file) throws Exception {
~>        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setExpandEntityReferences(false);
        factory.setValidating(false);
        return factory.newDocumentBuilder().parse(file);
    }
}
