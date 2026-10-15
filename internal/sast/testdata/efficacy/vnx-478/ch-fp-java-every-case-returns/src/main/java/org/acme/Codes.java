package org.acme;

public class Codes {
    String label(int code) {
        String text = null;
        switch (code) {
            case 200:
                text = "ok";
                break;
            case 404:
                text = "missing";
                break;
        }
        return text != null ? text : "unknown";
    }
}
