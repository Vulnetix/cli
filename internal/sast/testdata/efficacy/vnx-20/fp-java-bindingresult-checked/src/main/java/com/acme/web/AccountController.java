package com.acme.web;

import javax.validation.Valid;
import javax.validation.Validator;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.PostMapping;

public class AccountController {
    private final Validator validator;

    @PostMapping("/account")
    public String update(@Valid AccountForm form, BindingResult result) {
        if (result.hasErrors()) {
            return "account";
        }
        service.update(form);
        return "redirect:/";
    }

    @PostMapping("/email")
    public String email(@Valid EmailForm form,
                        BindingResult result) {
        if (rejected(result)) {
            return "email";
        }
        return "redirect:/";
    }

    public void check(AccountForm form) {
        Set<ConstraintViolation<AccountForm>> violations = validator.validate(form);
        if (!violations.isEmpty()) {
            throw new ConstraintViolationException(violations);
        }
    }

    public boolean valid(AccountForm form) {
        return validator.validate(form).isEmpty();
    }
}
