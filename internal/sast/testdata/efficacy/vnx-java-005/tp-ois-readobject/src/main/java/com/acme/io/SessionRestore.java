package com.acme.io;

import java.io.ObjectInputStream;
import javax.servlet.http.HttpServletRequest;

public class SessionRestore {
    public Object restore(HttpServletRequest request) throws Exception {
        ObjectInputStream in = new ObjectInputStream(request.getInputStream());
~>        Object state = in.readObject();
~>        Object extra = in.readUnshared();
        return new Object[] {state, extra};
    }
}
