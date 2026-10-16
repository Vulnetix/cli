package com.acme.ws;

import javax.jws.WebMethod;
import javax.jws.WebService;

@WebService
public class UserEndpoint {

    @WebMethod
    public boolean changePassword(String user, String oldPw, String newPw) {
        return auth.change(user, oldPw, newPw);
    }

    @WebMethod
    public String getPasswordPolicy() {
        return policy.describe();
    }

    @WebMethod
    public boolean testConnection() {
        return true;
    }

    @WebMethod
    public String executeOrder(String orderId) {
        return orders.execute(orderId);
    }
}
