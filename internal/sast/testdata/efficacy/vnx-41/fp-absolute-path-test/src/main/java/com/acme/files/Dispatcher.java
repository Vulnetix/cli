package com.acme.files;

public class Dispatcher {
    Response dispatch(Request request) {
        String path = request.getPath();
        if (!path.startsWith("/") || path.contains("..")) {
            return Response.notFound();
        }
        return Response.ok(path);
    }
}
