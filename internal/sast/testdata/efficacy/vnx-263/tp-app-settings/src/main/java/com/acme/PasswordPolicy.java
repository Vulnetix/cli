package com.acme;

import java.time.Duration;

public final class PasswordPolicy {
~>    public static final Duration PASSWORD_LIFETIME = Duration.ofDays(1000);
~>    public static final int PASSWORD_EXPIRATION_DAYS = 360;
    public static final int MIN_LENGTH = 12;
}
