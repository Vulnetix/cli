package com.acme.struts;

import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import ognl.Ognl;
import ognl.OgnlContext;

public class Binder {
    public Object bind(HttpServletRequest request, OgnlContext context) throws Exception {
        Map<String, String[]> params = request.getParameterMap();
        return Ognl.getValue("user.displayName", context, params);
    }
}
