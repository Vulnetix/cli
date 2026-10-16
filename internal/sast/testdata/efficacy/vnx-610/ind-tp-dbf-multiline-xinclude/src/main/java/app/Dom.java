package app;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;

public class Dom {
    DocumentBuilderFactory factory() throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
~>        f.setFeature(
            "http://apache.org/xml/features/disallow-doctype-decl",
            false);
~>        f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, false);
~>        f.setXIncludeAware(true);
        return f;
    }
}
