package com.acme.el;

import javax.el.ELContext;
import javax.el.ELProcessor;
import javax.el.ExpressionFactory;
import javax.el.ValueExpression;
import javax.servlet.http.HttpServletRequest;

public class ElRenderer {
    private final ExpressionFactory factory = ExpressionFactory.newInstance();

    Object render(HttpServletRequest req, ELContext ctx) {
        String template = req.getParameter("template");
~>        ValueExpression ve = factory.createValueExpression(ctx, template, Object.class);
        ELProcessor elp = new ELProcessor();
~>        Object out = elp.eval(req.getParameter("el"));
        return ve.getValue(ctx);
    }
}
