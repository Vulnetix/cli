package app;

import javax.xml.XMLConstants;
import javax.xml.transform.TransformerFactory;
import javax.xml.validation.SchemaFactory;

public class Access {
    void lock(TransformerFactory tf, SchemaFactory sf) throws Exception {
        tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
        sf.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        sf.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
    }
}
