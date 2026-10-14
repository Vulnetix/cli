package com.acme.xml;

import java.io.InputStream;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import org.dom4j.io.SAXReader;
import org.jdom2.input.SAXBuilder;

public class Importer {
    public void load(InputStream xml, InputStream xslt, java.io.Writer out) throws Exception {
~>        SAXReader reader = new SAXReader();
        reader.read(xml);
~>        SAXBuilder builder = new SAXBuilder();
        builder.build(xml);
~>        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer t = tf.newTransformer(new StreamSource(xslt));
        t.transform(new StreamSource(xml), new StreamResult(out));
    }
}
