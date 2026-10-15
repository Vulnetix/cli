package com.acme.profile;

import java.util.Objects;
import java.util.Optional;

public class SafeProfileService {
    public String displayName(User user) {
        return Optional.ofNullable(user)
                .map(User::getProfile)
                .map(Profile::getDisplayName)
                .orElse("anonymous");
    }

    public void require(User user) {
        Objects.requireNonNull(user, "user");
        if (user.getProfile() == null) {
            throw new NullPointerException("profile");
        }
    }

    public void handle(Runnable r) {
        try {
            r.run();
        } catch (IllegalStateException e) {
            log.warn("failed", e);
        }
    }
}
