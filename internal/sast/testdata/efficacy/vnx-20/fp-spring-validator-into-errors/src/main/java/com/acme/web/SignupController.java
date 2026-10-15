package com.acme.web;

import org.springframework.validation.BindingResult;

public class SignupController {
    private final SignupValidator signupValidator;

    public String signup(SignupForm form, BindingResult bindingResult) {
        signupValidator.validate(form, bindingResult);
        if (bindingResult.hasErrors()) {
            return "signup";
        }
        return "redirect:/";
    }
}
