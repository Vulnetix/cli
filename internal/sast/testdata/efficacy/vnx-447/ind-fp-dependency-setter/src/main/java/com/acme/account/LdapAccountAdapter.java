package com.acme.account;

import org.hibernate.SessionFactory;
import org.springframework.security.crypto.password.PasswordEncoder;

public class LdapAccountAdapter extends AbstractAccountAdapter {

    private SessionFactory sessionFactory;

    @Override
    public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
        // no-op: LDAP binds verify passwords server-side
    }

    public void setSessionFactory(SessionFactory sessionFactory) {
        this.sessionFactory = sessionFactory;
    }
}
