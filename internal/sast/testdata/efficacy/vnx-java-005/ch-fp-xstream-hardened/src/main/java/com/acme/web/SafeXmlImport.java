package com.acme.web;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.security.NoTypePermission;

public class SafeXmlImport {
    private final XStream xstream;

    public SafeXmlImport() {
        xstream = new XStream();
        xstream.addPermission(NoTypePermission.NONE);
        xstream.allowTypesByWildcard(new String[] {"com.acme.model.**"});
    }

    public Object read(String xml) {
        return xstream.fromXML(xml);
    }
}
