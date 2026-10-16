package com.acme;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

public class NameValidator implements ConstraintValidator<ValidName, String> {
    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (value == null || value.length() < 3) {
            context.disableDefaultConstraintViolation();
~>            context.buildConstraintViolationWithTemplate("Invalid name: " + value).addConstraintViolation();
            return false;
        }
        return true;
    }
}
