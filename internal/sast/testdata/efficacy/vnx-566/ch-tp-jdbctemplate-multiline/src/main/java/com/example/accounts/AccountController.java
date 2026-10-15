package com.example.accounts;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AccountController {
    private final JdbcTemplate jdbc;

    public AccountController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @GetMapping("/accounts/{accountId}")
    public Account show(@PathVariable("accountId") long accountId) {
        return jdbc.queryForObject(
~>            "SELECT id, holder, balance FROM accounts WHERE account_id = ?",
            new AccountMapper(),
            accountId);
    }
}
