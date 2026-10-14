package com.acme.io;

import com.thoughtworks.xstream.XStream;

public class ContactImport {
    public Contact parse(String payload) {
        XStream xstream = new XStream();
        xstream.alias("contact", Contact.class);
~>        return (Contact) xstream.fromXML(payload);
    }
}
