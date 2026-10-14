package com.acme.struts;

import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import ognl.Ognl;
import ognl.OgnlContext;
import com.opensymphony.xwork2.ognl.OgnlUtil;

public class OgnlEval {
    private OgnlUtil ognlUtil;

    Object eval(HttpServletRequest request, Map<String, Object> ctx, Object root) throws Exception {
        String path = request.getParameter("path");
~>        Object value = Ognl.getValue(path, ctx, root);
~>        ognlUtil.setValue(request.getParameter("name"), ctx, root, "x");
~>        Object tree = Ognl.parseExpression(
                request.getParameter("tree"));
        return value;
    }
}
