---
title: "VNX-JAVA-002 – Spring Actuator Endpoints Exposed"
description: "Detects Spring Boot configuration that exposes all actuator endpoints via management.endpoints.web.exposure.include=*, leaking heap dumps, environment variables, and enabling remote shutdown."
---

## Overview

This rule detects Spring Boot configuration files (`application.properties`, `application.yml`, or environment-specific variants) that set `management.endpoints.web.exposure.include` to the wildcard value `*`. This single configuration change exposes every registered actuator endpoint over HTTP, including endpoints that can reveal secrets, crash the JVM, or reconfigure the running application without a restart. The behaviour is covered by CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor).

**Severity:** Medium | **CWE:** [CWE-200 – Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

## Why This Matters

Spring Boot Actuator ships with endpoints that are extraordinarily powerful in a development context but dangerous when exposed to the internet or to untrusted internal networks. The `/actuator/heapdump` endpoint produces a full Java heap snapshot that can be analysed offline with tools like Eclipse Memory Analyzer to extract plaintext passwords, JWTs, database credentials, and private keys that happen to be live objects at the time of the dump.

The `/actuator/env` endpoint lists every environment variable, system property, and `@ConfigurationProperties` value — including those that Spring partially masks but that can sometimes be unmasked by other endpoints. The `/actuator/shutdown` endpoint, when enabled, lets any unauthenticated caller terminate the JVM process. The `/actuator/loggers` endpoint allows changing log levels at runtime, which can be abused to force verbose logging of secrets. Real-world breaches (including incidents tied to Alibaba Cloud and misconfigured Kubernetes deployments) have involved exposed actuator endpoints as initial access vectors.

## What Gets Flagged

The rule matches any Spring Boot properties or YAML file where the actuator exposure line is set to `*`.

```properties
# FLAGGED: wildcard exposes every actuator endpoint
management.endpoints.web.exposure.include=*
```

```yaml
# FLAGGED: YAML form of the same misconfiguration
management:
  endpoints:
    web:
      exposure:
        include: "*"
```

## Remediation

1. **Restrict the exposed endpoint list to only what operations requires.** The `health` and `info` endpoints are safe for most applications to expose publicly. All others should be off by default.

   ```properties
   # SAFE: only health and info are exposed over HTTP
   management.endpoints.web.exposure.include=health,info
   management.endpoint.health.show-details=when_authorized
   ```

2. **Move the actuator management port off the application port.** Configure a separate port bound only to `127.0.0.1` or a private network interface. This ensures that even if all endpoints are enabled for internal tooling, they are unreachable from the public internet.

   ```properties
   # SAFE: management endpoints on a separate port, not externally routed
   management.server.port=8081
   management.server.address=127.0.0.1
   ```

3. **Secure actuator endpoints with Spring Security.** If you need to expose endpoints such as `metrics` or `loggers` to an internal monitoring system, require authentication. The following Spring Security configuration locks down the actuator path:

   ```java
   // SAFE: actuator endpoints require ADMIN role
   @Bean
   public SecurityFilterChain actuatorSecurity(HttpSecurity http) throws Exception {
       http
           .securityMatcher("/actuator/**")
           .authorizeHttpRequests(auth -> auth
               .requestMatchers("/actuator/health", "/actuator/info").permitAll()
               .anyRequest().hasRole("ADMIN")
           )
           .httpBasic(Customizer.withDefaults());
       return http.build();
   }
   ```

4. **Explicitly disable sensitive individual endpoints.** Even if you restrict exposure, explicitly disable endpoints you will never use:

   ```properties
   management.endpoint.shutdown.enabled=false
   management.endpoint.heapdump.enabled=false
   management.endpoint.env.enabled=false
   ```

5. **Use environment-specific profiles.** Never let a `application-dev.properties` file with wildcard exposure be present on the classpath in production. Use Spring profiles (`spring.profiles.active=prod`) and ensure the CI/CD pipeline validates that no `include=*` lines are present in production configurations.

## References

- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CAPEC-116: Excavation](https://capec.mitre.org/data/definitions/116.html)
- [MITRE ATT&CK T1190 – Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [Spring Boot Actuator documentation](https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html)
- [Spring Security – Securing Actuator endpoints](https://docs.spring.io/spring-security/reference/servlet/integrations/actuator.html)
- [OWASP Top 10 A05:2021 – Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- [OWASP ASVS V14 – Configuration](https://owasp.org/www-project-application-security-verification-standard/)
