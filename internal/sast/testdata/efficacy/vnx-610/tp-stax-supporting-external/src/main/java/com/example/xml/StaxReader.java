package com.example.xml;

import javax.xml.stream.XMLInputFactory;

public class StaxReader {
    XMLInputFactory factory() {
        XMLInputFactory xif = XMLInputFactory.newInstance();
~>        xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, true);
~>        xif.setProperty("javax.xml.stream.isSupportingExternalEntities", Boolean.TRUE);
        return xif;
    }
}
