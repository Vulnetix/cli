package com.acme.rules;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class CouponCodeValidator implements ConstraintValidator<CouponCode, String> {

    @Override
    public boolean isValid(String code, ConstraintValidatorContext context) {
        if (code != null && code.matches("[A-Z]{4}-\\d{4}")) {
            return true;
        }
        context.disableDefaultConstraintViolation();
        String message = String.format("'%s' is not a valid coupon", code);
~>        context.buildConstraintViolationWithTemplate(message)
            .addConstraintViolation();
        return false;
    }
}
