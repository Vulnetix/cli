package com.acme.greet;

import javax.servlet.http.HttpServletRequest;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.common.TemplateParserContext;
import org.springframework.expression.spel.standard.SpelExpressionParser;

public class GreetingController {
    private final ExpressionParser parser = new SpelExpressionParser();

    public String greet(HttpServletRequest request) {
~>        Expression exp = parser.parseExpression(
                request.getHeader("X-Greeting"),
                new TemplateParserContext());
        return exp.getValue(String.class);
    }
}
