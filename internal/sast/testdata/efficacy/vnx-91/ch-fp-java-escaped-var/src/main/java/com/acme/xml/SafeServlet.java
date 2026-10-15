package com.acme.xml;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilderFactory;
import org.apache.commons.text.StringEscapeUtils;

public class SafeServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String user = @@sample:S[t]ri[n]gE[s]ca[p]eU[t]il[s][.]e[s]ca[p]eX[m]l1[1]@@(request.getParameter("user"));
        String xml = "<profile><name>" + user + "</name></profile>";
        response.setContentType("application/xml");
        response.getWriter().write(xml);
    }
}
