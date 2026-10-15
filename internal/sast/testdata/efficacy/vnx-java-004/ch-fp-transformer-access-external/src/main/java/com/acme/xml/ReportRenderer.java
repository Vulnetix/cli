package com.acme.xml;

import java.io.File;
import java.io.StringWriter;
import javax.xml.XMLConstants;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

public class ReportRenderer {
    public String render(File xsl, File data) throws Exception {
        TransformerFactory tf = TransformerFactory.newInstance();
        tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
        Transformer t = tf.newTransformer(new StreamSource(xsl));
        StringWriter out = new StringWriter();
        t.transform(new StreamSource(data), new StreamResult(out));
        return out.toString();
    }
}
