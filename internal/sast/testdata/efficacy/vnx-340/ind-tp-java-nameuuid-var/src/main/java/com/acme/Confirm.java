package com.acme;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

public class Confirm {
    public void send(User user) {
~>        UUID id = UUID.nameUUIDFromBytes(user.getEmail().getBytes(StandardCharsets.UTF_8));
        String raw = id.toString();
        user.setConfirmationToken(raw);
        mailer.sendConfirmation(user);
    }
}
