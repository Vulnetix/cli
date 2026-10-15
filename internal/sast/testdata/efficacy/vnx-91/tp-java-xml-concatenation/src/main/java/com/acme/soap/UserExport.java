package com.acme.soap;

import java.io.StringReader;
import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.xml.sax.InputSource;

public class UserExport {
    public Object export(HttpServletRequest request) throws Exception {
~>        String xml = "<user><name>" + request.getParameter("name") + "</name>";
        String role = request.getParameter("role");
~>        xml += "<role>" + role + "</role></user>";
        DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        return db.parse(new InputSource(new StringReader(xml)));
    }
}
