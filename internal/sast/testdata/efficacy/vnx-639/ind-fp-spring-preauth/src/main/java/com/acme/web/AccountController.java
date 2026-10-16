package com.acme.web;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/accounts")
public class AccountController {
    private final AccountRepository accountRepository;

    public AccountController(AccountRepository accountRepository) {
        this.accountRepository = accountRepository;
    }

    @PreAuthorize("@accountSecurity.isOwner(#accountId, authentication)")
    @GetMapping("/{accountId}")
    public Account get(@PathVariable("accountId") Long accountId) {
        return accountRepository.findById(accountId).orElseThrow();
    }

    public Account internal(Long accountId) {
        return accountRepository.findById(accountId).orElseThrow();
    }
}
