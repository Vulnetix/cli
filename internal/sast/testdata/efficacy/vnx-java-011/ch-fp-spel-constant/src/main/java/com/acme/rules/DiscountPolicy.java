package com.acme.rules;

import javax.servlet.http.HttpServletRequest;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;

public class DiscountPolicy {
    private static final String RULE = "#order.total > 100 and #order.customer.vip";
    private final ExpressionParser parser = new SpelExpressionParser();

    public boolean applies(Order order, HttpServletRequest request) {
        String coupon = request.getParameter("coupon");
        StandardEvaluationContext ctx = new StandardEvaluationContext();
        ctx.setVariable("order", order);
        ctx.setVariable("coupon", coupon);
        Expression exp = parser.parseExpression(RULE);
        Expression other = parser.parseExpression("#coupon != null");
        return Boolean.TRUE.equals(exp.getValue(ctx, Boolean.class)) || Boolean.TRUE.equals(other.getValue(ctx, Boolean.class));
    }
}
