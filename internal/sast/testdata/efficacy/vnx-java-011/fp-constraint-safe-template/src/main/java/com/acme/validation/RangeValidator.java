package com.acme.validation;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

public class RangeValidator implements ConstraintValidator<InRange, Integer> {
    @Override
    public boolean isValid(Integer value, ConstraintValidatorContext context) {
        if (value == null || value < 100) {
            return true;
        }
        context.disableDefaultConstraintViolation();
        context.buildConstraintViolationWithTemplate("{com.acme.InRange.message}")
            .addPropertyNode("amount")
            .addConstraintViolation();
        HibernateConstraintValidatorContext h = context.unwrap(HibernateConstraintValidatorContext.class);
        h.addMessageParameter("value", value)
            .buildConstraintViolationWithTemplate("Value {value} too large")
            .addConstraintViolation();
        return false;
    }
}
