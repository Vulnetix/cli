package com.acme.web;

import javax.validation.Valid;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class RegistrationController {
    private final UserService users;

    public RegistrationController(UserService users) {
        this.users = users;
    }

    @PostMapping("/register")
~>    public String register(@Valid @ModelAttribute("user") UserForm form, BindingResult result, Model model) {
        users.create(form);
        model.addAttribute("name", form.getName());
        return "welcome";
    }

    @PostMapping("/profile")
    public String profile(
            @Valid @ModelAttribute("profile") ProfileForm form,
~>            BindingResult bindingResult) {
        users.updateProfile(form);
        return "redirect:/profile";
    }

    @PostMapping("/address")
    public String address(@Valid AddressForm form, BindingResult errors) {
        if (errors.hasErrors()) {
            return "address";
        }
        users.updateAddress(form);
        return "redirect:/";
    }
}
