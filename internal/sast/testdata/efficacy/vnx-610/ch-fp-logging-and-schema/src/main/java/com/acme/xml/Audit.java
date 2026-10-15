package com.acme.xml;

import java.util.logging.Logger;

public class Audit {
    private static final Logger LOG = Logger.getLogger("audit");

    void warn() {
        LOG.warning("never call setFeature(load-external-dtd, true) on untrusted input");
        String hint = "spf.setFeature(\"http://xml.org/sax/features/external-general-entities\", true)";
        LOG.info(hint);
        // spf.setFeature("http://xml.org/sax/features/external-general-entities", true);
    }
}
