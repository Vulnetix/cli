package com.acme;

public class AccountLockoutService {
    private static final int MAX_FAILURES = 5;
    private final UserRepository users;

    public AccountLockoutService(UserRepository users) {
        this.users = users;
    }

    public void onFailedLogin(String username) {
        UserAccount account = users.findByUsername(username);
        account.incrementFailures();
        if (account.failures() >= MAX_FAILURES) {
            account.lock();
        }
        users.save(account);
    }
}
