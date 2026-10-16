package com.acme.cfg;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class MailSettings {
    @Value("${mail.smtp.password}")
    String smtpPassword;

    @Value("${mail.api-key}") String apiKey;

    interface Defaults {
        String TOKEN = "unused";
    }

    static class Nested {
        String secret;
    }
}
