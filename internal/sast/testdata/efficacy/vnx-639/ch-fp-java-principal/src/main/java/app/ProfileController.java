package app;

@RestController
public class ProfileController {
    @PreAuthorize("@guard.ownsAccount(#accountId, authentication)")
    @GetMapping("/accounts/{accountId}")
    public Account get(@PathVariable Long accountId) {
        return accountRepository.findById(accountId).orElseThrow();
    }

    @GetMapping("/me")
    public User me(Principal principal) {
        return userRepository.findById(principal.getName()).orElseThrow();
    }
}
