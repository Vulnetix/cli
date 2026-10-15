package com.acme.xml;

import java.io.File;
import org.dom4j.Document;
import @@sample:o[r]g[.][d]om[4]j[.][i]o[.][S]AX[R]ea[d]er@@;

public class SafeConfigLoader {
    public Document read(File upload) throws Exception {
        SAXReader saxReader = new SAXReader();
        saxReader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        return saxReader.read(upload);
    }
}
