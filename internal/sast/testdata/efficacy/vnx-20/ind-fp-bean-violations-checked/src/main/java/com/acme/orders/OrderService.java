package com.acme.orders;

import java.util.Set;
import javax.validation.ConstraintViolation;
import javax.validation.ConstraintViolationException;
import javax.validation.Validator;
import org.springframework.validation.Errors;

public class OrderService {

    private final Validator validator;
    private final org.springframework.validation.Validator springValidator;

    public OrderService(Validator validator, org.springframework.validation.Validator springValidator) {
        this.validator = validator;
        this.springValidator = springValidator;
    }

    public void place(Order order) {
        Set<ConstraintViolation<Order>> violations = validator.validate(order);
        if (!violations.isEmpty()) {
            throw new ConstraintViolationException(violations);
        }
    }

    public void check(Order order, Errors errors) {
        springValidator.validate(order, errors);
    }

    public boolean ok(Order order) {
        return validator.validate(order).isEmpty();
    }
}
