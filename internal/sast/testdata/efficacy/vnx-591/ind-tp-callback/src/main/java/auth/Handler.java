package auth;

import javax.security.auth.callback.*;

public class Handler implements CallbackHandler {
    public void handle(Callback[] callbacks) {
        for (Callback cb : callbacks) {
            if (cb instanceof PasswordCallback) {
                PasswordCallback pc = (PasswordCallback) cb;
~>                String text = new String(pc.getPassword());
                remember(text);
            }
        }
    }
}
