package com.acme.api;

import java.lang.reflect.Method;
import javax.servlet.http.HttpServletRequest;

public class ActionController {
    private final AccountService service = new AccountService();

    public Object dispatch(HttpServletRequest req) throws Exception {
        String action = req.getParameter("action");
~>        Method m = service.getClass().getMethod(action, String.class);
        return m.invoke(service, req.getParameter("id"));
    }
}
