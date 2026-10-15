package com.acme.loans;

@RestController
public class LoanController {
    @PostMapping("/loans/{id}/decision")
    public Loan decide(@PathVariable long id, @RequestParam String status) {
        Loan loan = loans.findById(id).orElseThrow();
~>        loan.setStatus(LoanStatus.valueOf(status));
        return loans.save(loan);
    }
}
