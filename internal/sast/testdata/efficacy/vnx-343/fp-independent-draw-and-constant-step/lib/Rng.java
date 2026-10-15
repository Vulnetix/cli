package lib;

import java.security.SecureRandom;

public class Rng {
    private final SecureRandom rng = new SecureRandom();

    public long sessionId() {
        long sessionId = rng.nextLong();
        return sessionId;
    }
}
