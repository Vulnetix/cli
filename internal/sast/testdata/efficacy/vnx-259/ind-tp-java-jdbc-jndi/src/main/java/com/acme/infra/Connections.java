package com.acme.infra;

import java.net.Authenticator;
import java.net.PasswordAuthentication;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Hashtable;
import javax.naming.Context;
import javax.naming.directory.InitialDirContext;

public final class Connections {
    private static final String URL = "jdbc:postgresql://db.internal:5432/billing";

    public static Connection billing(String user) throws SQLException {
~>        return DriverManager.getConnection(URL, user, "Pr0d-Db-Pa55");
    }

    public static InitialDirContext directory() throws Exception {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://ldap.internal:389");
        env.put(Context.SECURITY_PRINCIPAL, "cn=svc-billing,ou=services,dc=acme,dc=com");
~>        env.put(Context.SECURITY_CREDENTIALS, "Ldap-B1nd-2022");
        return new InitialDirContext(env);
    }

    static Authenticator proxyAuth(final String user) {
        return new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
~>                return new PasswordAuthentication(user, "Pr0xy-Gate!".toCharArray());
            }
        };
    }
}
