package com.acme.web;

@RestController
public class AccountController {
    @GetMapping("/accounts/{accountId}")
    public Account get(@PathVariable("accountId") Long accountId) {
~>        return accountRepository.findById(accountId).orElseThrow();
    }

    @DeleteMapping("/statements")
    public void delete(@RequestParam long statementId) {
~>        statementRepository.deleteById(statementId);
    }

    @GetMapping("/legacy")
    public Account legacy(HttpServletRequest request) {
~>        return accountDao.findById(Long.valueOf(request.getParameter("id")));
    }
}
