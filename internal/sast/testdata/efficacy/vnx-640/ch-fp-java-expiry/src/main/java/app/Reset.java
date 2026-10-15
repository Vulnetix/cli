package app;

import java.security.SecureRandom;

public class Reset {
    private final SecureRandom rng = new SecureRandom();

    public void start(User user) {
        long resetTokenExpiry = System.currentTimeMillis() + TTL_MS;
        byte[] buf = new byte[32];
        rng.nextBytes(buf);
        String resetToken = @@sample:B[a]se[6]4[.][g]et[U]rl[E]nc[o]de[r]@@().encodeToString(buf);
        user.setReset(resetToken, resetTokenExpiry);
    }
}
