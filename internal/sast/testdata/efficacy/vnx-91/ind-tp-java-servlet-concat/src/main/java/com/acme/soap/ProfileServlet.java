package com.acme.soap;

import java.io.IOException;
import java.io.StringReader;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

public class ProfileServlet extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
~>        String xml = "<user><name>" + request.getParameter("name") + "</name><role>member</role></user>";
        try {
            DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
            Document doc = db.parse(new InputSource(new StringReader(xml)));
            ProfileStore.save(doc);
        } catch (Exception e) {
            response.sendError(400);
        }
    }
}
