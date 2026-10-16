package com.acme.ser;

import java.beans.XMLDecoder;
import java.io.InputStream;
import java.io.Reader;
import com.thoughtworks.xstream.XStream;

public class Xml {
    public Object viaXStream(Reader r) {
        XStream xstream = new XStream();
~>        Object data = xstream.fromXML(r);
        return data;
    }

    public Object viaDecoder(InputStream in) {
~>        XMLDecoder decoder = new XMLDecoder(in);
        return decoder.readObject();
    }
}
