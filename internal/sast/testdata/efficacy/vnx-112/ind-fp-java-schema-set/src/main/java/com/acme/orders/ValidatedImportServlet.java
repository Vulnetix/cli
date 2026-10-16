package com.acme.orders;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import org.w3c.dom.Document;

public class ValidatedImportServlet extends HttpServlet {
    private static Schema schema;

    @Override
    public void init() {
        try {
            SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            schema = sf.newSchema(getClass().getResource("/order.xsd"));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            dbf.setSchema(schema);
            DocumentBuilder db = dbf.newDocumentBuilder();
            db.setErrorHandler(new StrictErrorHandler());
            Document doc = db.parse(request.getInputStream());
            response.setStatus(doc == null ? 400 : 201);
        } catch (Exception e) {
            response.sendError(400);
        }
    }
}
