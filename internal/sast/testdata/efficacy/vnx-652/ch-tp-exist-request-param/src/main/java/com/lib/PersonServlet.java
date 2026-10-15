package com.lib;

import org.xmldb.api.base.ResourceSet;
import org.xmldb.api.modules.XQueryService;
import javax.servlet.http.HttpServletRequest;

public class PersonServlet {
    ResourceSet lookup(XQueryService service, HttpServletRequest request) throws Exception {
~>        ResourceSet result = service.query("//person[name='" + request.getParameter("name") + "']");
        return result;
    }
}
