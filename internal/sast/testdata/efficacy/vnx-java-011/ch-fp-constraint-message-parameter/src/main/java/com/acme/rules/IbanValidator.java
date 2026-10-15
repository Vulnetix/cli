package com.acme.rules;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.hibernate.validator.constraintvalidation.HibernateConstraintValidatorContext;

public class IbanValidator implements ConstraintValidator<Iban, String> {

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (value == null || value.length() >= 15) {
            return true;
        }
        HibernateConstraintValidatorContext hctx = context.unwrap(HibernateConstraintValidatorContext.class);
        hctx.disableDefaultConstraintViolation();
        hctx.addMessageParameter("value", value)
            .buildConstraintViolationWithTemplate("{com.acme.Iban.tooShort} {value}")
            .addConstraintViolation();
        return false;
    }
}
