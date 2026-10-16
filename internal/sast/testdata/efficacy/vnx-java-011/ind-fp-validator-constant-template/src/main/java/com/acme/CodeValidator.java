package com.acme;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

public class CodeValidator implements ConstraintValidator<ValidCode, String> {
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (value == null || !value.matches("[A-Z]{4}")) {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate("{acme.code.invalid}").addConstraintViolation();
            return false;
        }
        return true;
    }
}
