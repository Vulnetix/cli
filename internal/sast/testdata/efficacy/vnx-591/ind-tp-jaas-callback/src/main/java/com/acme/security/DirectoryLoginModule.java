package com.acme.security;

import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

public class DirectoryLoginModule implements LoginModule {

    private CallbackHandler callbackHandler;
    private DirectoryClient directory;

    @Override
    public void initialize(Subject subject, CallbackHandler handler,
                           Map<String, ?> sharedState, Map<String, ?> options) {
        this.callbackHandler = handler;
        this.directory = DirectoryClient.fromOptions(options);
    }

    @Override
    public boolean login() throws LoginException {
        NameCallback nameCb = new NameCallback("Username: ");
        PasswordCallback passCb = new PasswordCallback("Password: ", false);
        try {
            callbackHandler.handle(new Callback[] { nameCb, passCb });
        } catch (Exception e) {
            throw new LoginException(e.getMessage());
        }
        String username = nameCb.getName();
~>        String password = new String(passCb.getPassword());
        passCb.clearPassword();
        return directory.bind(username, password);
    }

    @Override
    public boolean commit() { return true; }

    @Override
    public boolean abort() { return true; }

    @Override
    public boolean logout() { return true; }
}
