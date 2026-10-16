package com.acme;

import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;

public class Defaults {
    private static final ExpressionParser PARSER = new SpelExpressionParser();

    public Object limit() {
        return PARSER.parseExpression("T(java.lang.Math).max(10, 20)").getValue();
    }
}
