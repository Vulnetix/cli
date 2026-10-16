package app;

import org.springframework.web.bind.annotation.*;

@RestController
public class AccountController {
    private final AccountRepository accountRepository;

    public AccountController(AccountRepository r) { this.accountRepository = r; }

    @GetMapping("/accounts/{accountId}")
    public Account get(@PathVariable("accountId") Long accountId) {
~>        return accountRepository.findById(accountId).orElseThrow();
    }
}
