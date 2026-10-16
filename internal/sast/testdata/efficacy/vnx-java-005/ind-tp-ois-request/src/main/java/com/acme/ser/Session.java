package com.acme.ser;

import java.io.ObjectInputStream;
import javax.servlet.http.HttpServletRequest;

public class Session {
    public Object load(HttpServletRequest request) throws Exception {
        ObjectInputStream in = new ObjectInputStream(request.getInputStream());
~>        Object state = in.readObject();
        return state;
    }
}
