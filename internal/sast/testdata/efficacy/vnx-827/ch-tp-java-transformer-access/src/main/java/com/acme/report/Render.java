package com.acme.report;

import javax.xml.XMLConstants;
import javax.xml.transform.TransformerFactory;
import javax.xml.validation.SchemaFactory;

public class Render {
    public TransformerFactory factory() {
        TransformerFactory tf = TransformerFactory.newInstance();
~>        tf.setAttribute("http://javax.xml.XMLConstants/property/accessExternalDTD", "file,http");
        return tf;
    }

    public SchemaFactory schemas() throws Exception {
        SchemaFactory sf = SchemaFactory.newInstance(@@sample:X[M]LC[o]ns[t]an[t]s[.][W]3C[_]XM[L][_]S[C]HE[M]A[_][N]S[_][U]RI@@);
~>        sf.setProperty(
            XMLConstants.ACCESS_EXTERNAL_DTD,
            "all");
        return sf;
    }
}
