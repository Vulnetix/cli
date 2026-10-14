package com.acme.validation;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

public class SkuValidator implements ConstraintValidator<Sku, String> {
    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (value == null || value.matches("[A-Z]{3}-\\d{4}")) {
            return true;
        }
        context.disableDefaultConstraintViolation();
~>        context.buildConstraintViolationWithTemplate("Invalid SKU: " + value)
            .addConstraintViolation();
        return false;
    }
}
