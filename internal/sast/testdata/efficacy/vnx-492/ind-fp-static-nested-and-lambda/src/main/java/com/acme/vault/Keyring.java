package com.acme.vault;

public class Keyring {
    private String secretToken;
    private String label;

    static class Entry {
        private String password;
        String masked() { return "****"; }
    }

    Runnable refresher() {
        return () -> secretToken = KeyService.rotate(secretToken);
    }

    class LabelView {
        String show() { return label.toUpperCase(); }
    }

    Runnable logger() {
        return new Runnable() {
            public void run() { System.out.println("label=" + label); }
        };
    }
}
