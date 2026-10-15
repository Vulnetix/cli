package app;

import org.springframework.security.web.authentication.www.DigestAuthenticationEntryPoint;

public class SecurityConfig {
    DigestAuthenticationEntryPoint entryPoint() {
~>        DigestAuthenticationEntryPoint ep = new DigestAuthenticationEntryPoint();
        ep.setRealmName("admin");
        ep.setKey("k");
        return ep;
    }
}
