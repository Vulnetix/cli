package com.acme.xml;

import java.io.File;
import java.io.StringWriter;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import org.xml.sax.XMLReader;

public class Pipelines {
    public XMLReader reader() throws Exception {
~>        return SAXParserFactory.newInstance().newSAXParser().getXMLReader();
    }

    public String transform(File xslt, File in) throws Exception {
~>        Transformer t = TransformerFactory.newInstance().newTransformer(new StreamSource(xslt));
        StringWriter w = new StringWriter();
        t.transform(new StreamSource(in), new StreamResult(w));
        return w.toString();
    }
}
