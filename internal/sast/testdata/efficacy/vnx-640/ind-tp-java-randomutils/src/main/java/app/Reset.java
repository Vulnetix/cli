package app;

import org.apache.commons.lang3.RandomStringUtils;

public class Reset {
    String make() {
~>        String resetToken = RandomStringUtils.randomAlphanumeric(32);
        return resetToken;
    }
}
