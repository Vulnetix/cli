package com.acme.web;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/accounts")
public class AccountController {
    private final AccountRepository accountRepository;

    public AccountController(AccountRepository accountRepository) {
        this.accountRepository = accountRepository;
    }

    @GetMapping("/{accountId}")
    public Account get(@PathVariable("accountId") Long accountId) {
~>        return accountRepository.findById(accountId).orElseThrow();
    }

    @DeleteMapping
    public void delete(@RequestParam Long id) {
~>        accountRepository.deleteById(id);
    }
}
