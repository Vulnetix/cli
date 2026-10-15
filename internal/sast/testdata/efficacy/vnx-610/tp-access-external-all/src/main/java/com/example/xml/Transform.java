package com.example.xml;

import javax.xml.XMLConstants;
import javax.xml.transform.TransformerFactory;
import javax.xml.validation.SchemaFactory;

public class Transform {
    void configure() throws Exception {
        TransformerFactory tf = TransformerFactory.newInstance();
~>        tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "all");
~>        tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "file,http,https");
        SchemaFactory sf = SchemaFactory.newInstance(@@sample:X[M]LC[o]ns[t]an[t]s[.][W]3C[_]XM[L][_]S[C]HE[M]A[_][N]S[_][U]RI@@);
~>        sf.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "http");
    }
}
