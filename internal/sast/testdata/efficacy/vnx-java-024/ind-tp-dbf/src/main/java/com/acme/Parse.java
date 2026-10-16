package com.acme;
import javax.xml.parsers.*;
import org.w3c.dom.Document;
public class Parse {
    Document parse(java.io.InputStream in) throws Exception {
~>        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder b = dbf.newDocumentBuilder();
        return b.parse(in);
    }
}
