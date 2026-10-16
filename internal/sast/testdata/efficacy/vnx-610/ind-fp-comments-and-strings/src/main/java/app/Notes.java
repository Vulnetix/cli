package app;

public class Notes {
    // never call setFeature("http://xml.org/sax/features/external-general-entities", true)
    /* tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "all"); */
    static final String WARNING = "do not use setXIncludeAware(true) on untrusted input";

    void unrelated(javax.xml.parsers.DocumentBuilderFactory f) {
        f.setNamespaceAware(true);
        f.setValidating(false);
        f.setIgnoringComments(true);
    }
}
