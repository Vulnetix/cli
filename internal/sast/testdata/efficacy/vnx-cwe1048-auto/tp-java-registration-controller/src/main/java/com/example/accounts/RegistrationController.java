package com.example.accounts;

import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RegistrationController {

    private static final Logger log = LoggerFactory.getLogger(RegistrationController.class);

    private final UserRepository users;
    private final PasswordPolicy policy;
    private final Mailer mailer;
    private final RateLimiter limiter;
    private final AuditTrail audit;

    public RegistrationController(UserRepository users, PasswordPolicy policy, Mailer mailer,
            RateLimiter limiter, AuditTrail audit) {
        this.users = users;
        this.policy = policy;
        this.mailer = mailer;
        this.limiter = limiter;
        this.audit = audit;
    }

    @PostMapping("/register")
~>    public ResponseEntity<RegistrationResult> register(@RequestBody RegistrationRequest request) {
        if (!limiter.tryAcquire(request.getClientIp())) {
            audit.recordThrottled(request.getClientIp());
            return ResponseEntity.status(429).build();
        }
        String email = request.getEmail().trim().toLowerCase(Locale.ROOT);
        if (!EmailValidator.isValid(email)) {
            return ResponseEntity.badRequest().body(RegistrationResult.invalid("email"));
        }
        Optional<User> existing = users.findByEmail(email);
        if (existing.isPresent()) {
            mailer.sendAccountExistsNotice(existing.get());
            return ResponseEntity.accepted().body(RegistrationResult.pending());
        }
        PolicyResult check = policy.evaluate(request.getPassword(), email);
        if (!check.passed()) {
            log.info("password rejected: {}", check.reason());
            return ResponseEntity.unprocessableEntity().body(RegistrationResult.weak(check.reason()));
        }
        if (BreachedPasswords.contains(request.getPassword())) {
            return ResponseEntity.unprocessableEntity().body(RegistrationResult.breached());
        }
        String hash = PasswordHasher.argon2id().hash(request.getPassword().toCharArray());
        User user = new User(email, hash);
        user.setDisplayName(Sanitizer.plainText(request.getDisplayName()));
        user.setLocale(Locale.forLanguageTag(request.getLocale()));
        user.setCreatedAt(Instant.now());
        user.setTermsVersion(Terms.currentVersion());
        users.save(user);

        VerificationToken token = TokenFactory.create(user.getId(), Duration.ofHours(24));
        users.storeToken(token);
        mailer.sendVerification(user, token.getValue());
        audit.recordRegistration(user.getId(), request.getClientIp());
        Metrics.counter("registrations").increment();
        log.debug("registered {}", user.getId());
        return ResponseEntity.ok(RegistrationResult.created(user.getId()));
    }
}
