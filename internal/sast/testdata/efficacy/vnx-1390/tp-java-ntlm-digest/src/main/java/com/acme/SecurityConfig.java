package com.acme;

import org.springframework.security.web.authentication.www.DigestAuthenticationFilter;

public class SecurityConfig {
    DigestAuthenticationFilter digestFilter() {
~>        DigestAuthenticationFilter filter = new DigestAuthenticationFilter();
        filter.setUserDetailsService(users);
        return filter;
    }
}
