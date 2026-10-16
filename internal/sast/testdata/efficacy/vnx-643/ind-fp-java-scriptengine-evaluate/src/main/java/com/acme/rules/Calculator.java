package com.acme.rules;

import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;

public class Calculator {
    private final ExpressionParser parser = new SpelExpressionParser();

    public Object discount(Order order) {
        String formula = "total * " + order.getRate();
        return parser.parseExpression("100 - 5").getValue();
    }

    public Object eval(MathEngine engine, Order order) {
        return engine.evaluate("price + " + order.getShipping());
    }
}
