package com.acme.ldap;

import java.util.Hashtable;
import javax.naming.Context;

public final class LdapConfig {
    public static Hashtable<String, String> env() {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.PROVIDER_URL, "ldap://ldap.staging.internal:389");
        // HACK: hard-coded credentials for the staging bind account
        env.put(Context.SECURITY_PRINCIPAL, System.getenv("LDAP_BIND_DN"));
        return env;
    }
}
