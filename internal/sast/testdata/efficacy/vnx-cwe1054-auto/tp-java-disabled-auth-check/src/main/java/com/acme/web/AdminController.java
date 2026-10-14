package com.acme.web;

public class AdminController {

    public Response deleteUser(Request request, long id) {
        // TODO put this back once the SSO migration is done
~>        // if (!request.user().hasRole("ADMIN")) {
        //     return Response.forbidden();
        // }
        // audit.record(request.user(), "user.delete", id);
        users.delete(id);
        return Response.noContent();
    }
}
