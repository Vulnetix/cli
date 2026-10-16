package com.acme.net;

import java.net.Authenticator;
import java.net.PasswordAuthentication;

public class ProxySetup {
    private final String proxyUser;
    private final String proxyPassword;

    public ProxySetup(String user, String password) {
        this.proxyUser = user;
        this.proxyPassword = password;
    }

    public void install() {
~>        Authenticator.setDefault(new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(proxyUser, proxyPassword.toCharArray());
            }
        });
    }
}
