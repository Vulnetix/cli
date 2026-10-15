package com.acme.xml;

import java.io.IOException;
import java.io.StringReader;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import @@sample:o[r]g[.][w]3c[.]do[m][.]D[o]cu[m]en[t]@@;
import org.xml.sax.InputSource;

public class ProfileServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String user = request.getParameter("user");
        String email = request.getParameter("email");
~>        String xml = "<profile><name>" + user + "</name>"
~>                + "<email>" + email + "</email><role>user</role></profile>";
        try {
            DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
            Document doc = db.parse(new InputSource(new StringReader(xml)));
            store(doc);
        } catch (Exception e) {
            response.sendError(400);
        }
    }

    private void store(Document doc) {}
}
