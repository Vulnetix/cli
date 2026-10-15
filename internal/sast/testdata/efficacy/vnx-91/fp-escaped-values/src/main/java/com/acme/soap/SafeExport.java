package com.acme.soap;

import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilder;
import org.apache.commons.text.StringEscapeUtils;

public class SafeExport {
    public String export(HttpServletRequest request) {
        String xml = "<user><name>" + @@sample:S[t]ri[n]gE[s]ca[p]eU[t]il[s][.]e[s]ca[p]eX[m]l1[0]@@(request.getParameter("name")) + "</name></user>";
        return xml;
    }
}
