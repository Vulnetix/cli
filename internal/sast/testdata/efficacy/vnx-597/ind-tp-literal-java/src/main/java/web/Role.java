package web;

import javax.servlet.http.HttpServletRequest;

public class Role {
    boolean isAdmin(String role) {
~>        return role == "admin";
    }

    boolean del(HttpServletRequest request) {
~>        if (request.getParameter("action") == "delete") {
            return true;
        }
        return false;
    }

    boolean notRoot(String user) {
~>        return user != "root";
    }
}
