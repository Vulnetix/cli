package app;

import org.springframework.web.bind.annotation.*;

@RestController
public class AccountController {
    @GetMapping("/accounts/{accountId}")
    public Account get(@PathVariable Long accountId) {
~>        return accountRepository.findById(accountId).orElseThrow();
    }

    @DeleteMapping("/accounts")
    public void delete(HttpServletRequest request) {
        Long id = Long.valueOf(request.getParameter("id"));
~>        accountRepository.deleteById(id);
    }
}
