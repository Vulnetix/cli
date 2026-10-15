package com.acme.soap;

import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilder;
import @@sample:o[r]g[.][w]3c[.]do[m][.]D[o]cu[m]en[t]@@;
import org.w3c.dom.Element;

public class DomExport {
    public Document export(DocumentBuilder db, HttpServletRequest request) {
        Document doc = db.newDocument();
        Element name = doc.createElement("name");
        name.setTextContent(request.getParameter("name"));
        doc.appendChild(name);
        return doc;
    }
}
