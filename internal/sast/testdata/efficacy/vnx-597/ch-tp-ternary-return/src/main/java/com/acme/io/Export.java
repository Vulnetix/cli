package com.acme.io;

public class Export {
    String ext(String type) {
~>        return type == "pdf" ? ".pdf" : ".txt";
    }
}
