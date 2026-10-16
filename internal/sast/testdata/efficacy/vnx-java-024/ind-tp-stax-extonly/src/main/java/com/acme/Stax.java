package com.acme;
import javax.xml.stream.*;
public class Stax {
    XMLStreamReader open(java.io.InputStream in) throws Exception {
~>        XMLInputFactory f = XMLInputFactory.newInstance();
        f.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        return f.createXMLStreamReader(in);
    }
}
