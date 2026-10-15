package app;

import java.util.Random;

public class ResetService {
    private static final Random RANDOM = new Random();

    public void startReset(User user) {
~>        String resetCode = String.valueOf(100000 + RANDOM.nextInt(900000));
~>        String tempPassword = RandomStringUtils.randomAlphanumeric(10);
        user.setResetCode(resetCode);
        mail.send(user, tempPassword);
    }
}
