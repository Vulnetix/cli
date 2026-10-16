package com.acme.io;

import java.io.IOException;
import java.sql.SQLException;

/**
 * Archive storage. Older revisions declared {@code throws Exception}; do not
 * reintroduce it.
 */
public class Archive {
    private static final String NOTE = "never write throws Exception here";

    public void store(byte[] data) throws IOException, SQLException {
        Store.write(data);
    }

    static void init() throws ExceptionInInitializerError {
        Store.init();
    }

    // public void legacy() throws Exception {
    public void purge() throws ArchiveException {
        Store.purge();
    }
}
