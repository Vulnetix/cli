package com.acme.xml;

import java.io.File;
import org.dom4j.Document;
import @@sample:o[r]g[.][d]om[4]j[.][i]o[.][S]AX[R]ea[d]er@@;

public class ConfigLoader {
    public Document read(File upload) throws Exception {
~>        SAXReader reader = new SAXReader();
        reader.setEncoding("UTF-8");
        return reader.read(upload);
    }
}
