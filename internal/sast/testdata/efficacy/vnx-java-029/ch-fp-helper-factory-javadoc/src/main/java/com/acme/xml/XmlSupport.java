package com.acme.xml;

import java.io.InputStream;
import javax.xml.parsers.DocumentBuilderFactory;
import @@sample:o[r]g[.][w]3c[.]do[m][.]D[o]cu[m]en[t]@@;

/**
 * Never call {@code DocumentBuilderFactory.newInstance()} directly; use
 * {@link XmlSecurity#newDocumentBuilderFactory()} which disables DTDs.
 */
public class XmlSupport {
    static final String HINT = "DocumentBuilderFactory.newInstance() must be hardened";

    public Document read(InputStream in) throws Exception {
        DocumentBuilderFactory dbf = XmlSecurity.newDocumentBuilderFactory();
        return dbf.newDocumentBuilder().parse(in);
    }

    public Document readOther(InputStream in) throws Exception {
        DocumentBuilderFactory other = DocumentBuilderFactory.newInstance();
        XmlSecurity.harden(other);
        return other.newDocumentBuilder().parse(in);
    }
}
