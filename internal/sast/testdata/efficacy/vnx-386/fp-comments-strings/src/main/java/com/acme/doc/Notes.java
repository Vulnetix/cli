package com.acme.doc;

public class Notes {
    // Class.forName(prefix + name) resolves whatever class the caller names
    static final String TIP = "avoid Class.forName(prefix + name)";

    /*
     * loader.loadClass(base + kind)
     */
    public String tip() {
        return TIP + count + "x";
    }
}
