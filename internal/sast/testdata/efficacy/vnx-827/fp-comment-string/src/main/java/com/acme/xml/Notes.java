package com.acme.xml;

public class Notes {
    // Do not call dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
    /* xif.setProperty(XMLInputFactory.SUPPORT_DTD, true) re-enables DTDs */
    static final String WARNING = "setFeature(disallow-doctype-decl, false) is unsafe";
    static final String DOC = "settings.DtdProcessing = DtdProcessing.Parse";

    void warn(org.slf4j.Logger log) {
        log.warn("never call xif.setProperty(XMLInputFactory.SUPPORT_DTD, true)");
    }
}
