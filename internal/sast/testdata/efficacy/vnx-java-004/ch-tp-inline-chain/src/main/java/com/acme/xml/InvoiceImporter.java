package com.acme.xml;

import java.io.InputStream;
import javax.xml.parsers.DocumentBuilderFactory;
import @@sample:o[r]g[.][w]3c[.]do[m][.]D[o]cu[m]en[t]@@;

public class InvoiceImporter {
    public Document load(InputStream in) throws Exception {
~>        return DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(in);
    }
}
