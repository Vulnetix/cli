package com.acme;
import javax.xml.stream.*;
public class StaxOk {
    XMLInputFactory make() {
        XMLInputFactory f = XMLInputFactory.newFactory();
        f.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        return f;
    }
}
