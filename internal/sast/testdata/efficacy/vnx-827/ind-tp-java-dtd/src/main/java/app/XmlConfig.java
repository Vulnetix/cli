package app;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.stream.XMLInputFactory;

public class XmlConfig {
    DocumentBuilderFactory build() throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
~>        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
        return dbf;
    }

    XMLInputFactory stax() {
        XMLInputFactory xif = XMLInputFactory.newInstance();
~>        xif.setProperty(XMLInputFactory.SUPPORT_DTD, true);
        return xif;
    }

    void access(javax.xml.transform.TransformerFactory tf) throws Exception {
~>        tf.setAttribute(
            javax.xml.XMLConstants.ACCESS_EXTERNAL_DTD,
            "all");
    }
}
