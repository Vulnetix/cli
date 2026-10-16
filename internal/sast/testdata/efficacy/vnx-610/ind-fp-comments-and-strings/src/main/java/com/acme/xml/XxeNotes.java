package com.acme.xml;

/**
 * Never write {@code reader.setFeature("http://xml.org/sax/features/external-general-entities", true)}
 * in this codebase.
 */
public final class XxeNotes {

    // Do NOT do this: dbf.setXIncludeAware(true);
    // nor tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "all");

    public static final String WARNING =
            "setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", false) is banned";

    private XxeNotes() {
    }
}
