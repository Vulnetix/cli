package app;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.stream.XMLInputFactory;

public class Safe {
    void a() throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        XMLInputFactory xif = XMLInputFactory.newInstance();
        xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        xif.setProperty("javax.xml.stream.isSupportingExternalEntities", false);
        dbf.setAttribute(javax.xml.XMLConstants.ACCESS_EXTERNAL_DTD, "");
        // dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
        String s = "xif.setProperty(XMLInputFactory.SUPPORT_DTD, true);";
    }
}
