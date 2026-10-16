package com.acme.web;

import javax.validation.Valid;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class SignupController {

    private final AccountService accounts;

    public SignupController(AccountService accounts) {
        this.accounts = accounts;
    }

    @PostMapping("/signup")
~>    public String signup(@Valid @ModelAttribute("account") SignupForm form, BindingResult bindingResult, Model model) {
        accounts.create(form.getEmail(), form.getPassword());
        model.addAttribute("email", form.getEmail());
        return "redirect:/welcome";
    }
}
