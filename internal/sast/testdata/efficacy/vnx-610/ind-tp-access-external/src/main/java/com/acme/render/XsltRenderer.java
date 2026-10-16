package com.acme.render;

import java.io.StringWriter;
import javax.xml.XMLConstants;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

public class XsltRenderer {

    private static final String GENERAL_ENTITIES = "http://xml.org/sax/features/external-general-entities";

    static {
~>        System.setProperty("javax.xml.accessExternalStylesheet", "all");
    }

    public String render(StreamSource xml, StreamSource xsl) throws Exception {
        TransformerFactory tf = TransformerFactory.newInstance();
~>        tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "all");
~>        tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "file,http");
        Transformer t = tf.newTransformer(xsl);
        StringWriter out = new StringWriter();
        t.transform(xml, new StreamResult(out));
        return out.toString();
    }

    public Schema schema(StreamSource xsd) throws Exception {
        SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
~>        sf.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA,
                "all");
        return sf.newSchema(xsd);
    }

    public javax.xml.parsers.SAXParserFactory sax() throws Exception {
        javax.xml.parsers.SAXParserFactory spf = javax.xml.parsers.SAXParserFactory.newInstance();
~>        spf.setFeature(GENERAL_ENTITIES, true);
        return spf;
    }
}
