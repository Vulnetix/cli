package com.example.xml;

import java.io.InputStream;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

public class InvoiceParser {
    // TODO: set disallow-doctype-decl on this factory
    public Document parse(InputStream in) throws Exception {
~>        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        dbf.setExpandEntityReferences(false);
        DocumentBuilder db = dbf.newDocumentBuilder();
        return db.parse(in);
    }

    public Document chained(InputStream in) throws Exception {
~>        return DocumentBuilderFactory.newInstance()
                .newDocumentBuilder()
                .parse(in);
    }
}
