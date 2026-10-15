package org.acme;

public class Dispatch {
    void handle(String verb, Request req) {
        Handler handler = null;
~>        switch (verb) {
            case "GET":
                handler = new GetHandler();
                break;
            case "POST":
                handler = new PostHandler();
                break;
        }
        handler.serve(req);
    }
}
