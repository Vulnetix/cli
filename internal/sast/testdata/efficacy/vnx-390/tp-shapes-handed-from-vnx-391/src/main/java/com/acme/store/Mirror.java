package com.acme.store;

import java.io.IOException;
import java.sql.SQLException;

public class Mirror {
    private final Bucket bucket;

    public Mirror(Bucket bucket) {
        this.bucket = bucket;
    }

    public void copy(String name) {
        try {
            bucket.copy(name);
~>      } catch(IOException io){ }
    }

    public void sync(String name) {
        try {
            bucket.sync(name);
~>      } catch (final IOException | SQLException failure) {

        }
    }

    public void drop(String name) {
        try { bucket.drop(name); }
~>      catch (final RuntimeException | IOException problem) { }
    }

    public void stat(String name) {
        try {
            bucket.stat(name);
~>      } catch (IOException statError) {
            statError.getLocalizedMessage();
        }
    }
}
