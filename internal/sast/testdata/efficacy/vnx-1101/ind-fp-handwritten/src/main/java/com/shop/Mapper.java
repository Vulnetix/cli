package com.shop;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;

public class Mapper {
    // see the generated classes under com.shop.gen
    public String toXml(Object o) throws Exception {
        Marshaller m = JAXBContext.newInstance(o.getClass()).createMarshaller();
        java.io.StringWriter w = new java.io.StringWriter();
        m.marshal(o, w);
        return w.toString();
    }
}
