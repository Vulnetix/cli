package com.acme.xml;

import java.io.File;
import javax.xml.XMLConstants;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

public class SchemaValidator {
    public void validate(File xsd, File xml) throws Exception {
~>        SchemaFactory sf = SchemaFactory.newInstance(@@sample:X[M]LC[o]ns[t]an[t]s[.][W]3C[_]XM[L][_]S[C]HE[M]A[_][N]S[_][U]RI@@);
        Schema schema = sf.newSchema(new StreamSource(xsd));
        schema.newValidator().validate(new StreamSource(xml));
    }
}
