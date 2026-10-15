package com.acme.api;

import javax.ws.rs.core.Response;

public class AccessResource {
    public Response grant(String user) {
        try {
            acl.grant(user);
            return Response.noContent().build();
        } catch (AclException e) {
~>            return Response.status(Response.Status.OK).entity("granted").build();
        }
    }

    public Boolean isAllowed(String user, String action) {
        try {
            return policy.evaluate(user, action);
        } catch (PolicyException e) {
~>            return true;
        }
    }

    public Response revoke(String user) {
        try {
            acl.revoke(user);
            return Response.ok().build();
        } catch (AclException e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        }
    }
}
