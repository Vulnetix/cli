package com.acme.doc;

public class Lint {
    // Do not write: catch (Exception e) {}
    static final String BAD = "catch (Exception e) {}";

    public String explain() {
        return "an empty block like catch (IOException e) { } hides failures";
    }
}
