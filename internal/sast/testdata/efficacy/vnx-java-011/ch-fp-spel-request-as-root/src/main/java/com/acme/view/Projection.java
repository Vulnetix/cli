package com.acme.view;

import javax.servlet.http.HttpServletRequest;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;

public class Projection {
    private static final ExpressionParser PARSER = new SpelExpressionParser();
    private static final Expression NAME = PARSER.parseExpression("name.toUpperCase()");

    public Object project(HttpServletRequest request) {
        String raw = request.getParameter("q");
        StandardEvaluationContext ctx = new StandardEvaluationContext(new Holder(raw));
        return NAME.getValue(ctx);
    }

    record Holder(String name) {}
}
