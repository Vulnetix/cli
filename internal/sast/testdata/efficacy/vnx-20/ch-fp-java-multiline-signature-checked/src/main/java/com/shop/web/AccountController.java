package com.shop.web;

import javax.validation.Valid;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class AccountController {
    private final AccountService accounts;

    public AccountController(AccountService accounts) {
        this.accounts = accounts;
    }

    @PostMapping("/accounts")
    public String create(
            @Valid AccountForm form,
            BindingResult bindingResult) {

        // reject before touching the service
        if (bindingResult.hasErrors())
            return "accounts/new";
        accounts.open(form);
        return "redirect:/accounts";
    }

    @PostMapping("/accounts/rename")
    public String rename(@Valid RenameForm form, BindingResult result, Model model) {
        return FormSupport.renderOrRedirect(result, model, () -> accounts.rename(form));
    }
}
