package com.acme.xml;

import java.io.InputStream;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import @@sample:o[r]g[.][w]3c[.]do[m][.]D[o]cu[m]en[t]@@;

public class ConfigReader {
    public Document read(InputStream in) throws Exception {
~>        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        return db.parse(in);
    }

    public Document quick(InputStream in) throws Exception {
~>        return DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(in);
    }
}
