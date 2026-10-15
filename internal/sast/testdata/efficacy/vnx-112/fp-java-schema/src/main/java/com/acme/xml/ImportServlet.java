package com.acme.xml;

import java.io.File;
import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

public class ImportServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            SchemaFactory sf = SchemaFactory.newInstance(@@sample:X[M]LC[o]ns[t]an[t]s[.][W]3C[_]XM[L][_]S[C]HE[M]A[_][N]S[_][U]RI@@);
            Schema schema = sf.newSchema(new File("order.xsd"));
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setSchema(schema);
            DocumentBuilder db = dbf.newDocumentBuilder();
            db.parse(request.getInputStream());
        } catch (Exception e) {
            response.sendError(400);
        }
    }
}
