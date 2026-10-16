package app;

import javax.xml.XMLConstants;
import javax.xml.stream.XMLInputFactory;
import javax.xml.transform.TransformerFactory;

public class Stax {
    void configure() {
        XMLInputFactory xif = XMLInputFactory.newInstance();
~>        xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, true);
        TransformerFactory tf = TransformerFactory.newInstance();
~>        tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "all");
~>        tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "file,http");
    }
}
