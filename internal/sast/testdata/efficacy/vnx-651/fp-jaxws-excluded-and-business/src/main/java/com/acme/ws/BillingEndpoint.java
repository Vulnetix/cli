package com.acme.ws;

import javax.jws.WebMethod;
import javax.jws.WebService;

@WebService
public class BillingEndpoint {

    @WebMethod
    public Invoice createInvoice(String customer) {
        return billing.create(customer);
    }

    @WebMethod(exclude = true)
    public void internalRebuildIndex() {
        index.rebuild();
    }

    public String debugState() {
        return state.toString();
    }

    @WebMethod
    public boolean changePassword(String user, String oldPw, String newPw) {
        return auth.change(user, oldPw, newPw);
    }
}
