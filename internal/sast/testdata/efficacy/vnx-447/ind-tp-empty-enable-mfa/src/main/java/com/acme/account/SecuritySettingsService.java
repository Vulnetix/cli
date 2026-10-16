package com.acme.account;

import org.springframework.stereotype.Service;

@Service
public class SecuritySettingsService {

    private final UserRepository users;

    public SecuritySettingsService(UserRepository users) {
        this.users = users;
    }

~>    public void enableTwoFactor(long userId) {
        // TODO wire up the TOTP enrolment once the auth team ships it
    }

    public UserSettings load(long userId) {
        return users.findSettings(userId);
    }
}
