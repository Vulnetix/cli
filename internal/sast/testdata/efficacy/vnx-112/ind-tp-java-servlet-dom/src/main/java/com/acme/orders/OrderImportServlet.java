package com.acme.orders;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.XMLConstants;
import org.w3c.dom.Document;

public class OrderImportServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            DocumentBuilder db = dbf.newDocumentBuilder();
~>            Document doc = db.parse(request.getInputStream());
            String qty = doc.getElementsByTagName("qty").item(0).getTextContent();
            OrderService.place(Integer.parseInt(qty));
            response.setStatus(201);
        } catch (Exception e) {
            response.sendError(400);
        }
    }
}
