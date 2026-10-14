package com.acme.xml;

import java.io.InputStream;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

public class InvoiceParser {
    public Document parse(InputStream body) throws Exception {
~>        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        dbf.setExpandEntityReferences(false);
        DocumentBuilder db = dbf.newDocumentBuilder();
        return db.parse(body);
    }

    public Document quick(InputStream body) throws Exception {
~>        return DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(body);
    }

    private static final DocumentBuilderFactory SHARED =
~>            DocumentBuilderFactory.newDefaultInstance();
}
