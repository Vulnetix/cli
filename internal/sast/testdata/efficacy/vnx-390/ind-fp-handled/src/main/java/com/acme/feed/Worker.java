package com.acme.feed;

import java.io.IOException;
import java.io.UncheckedIOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Worker {
    private static final Logger log = LoggerFactory.getLogger(Worker.class);

    public void run(Feed feed) {
        try {
            feed.fetch();
        } catch (IOException e) {
            log.warn("cannot fetch {}", feed.url(), e);
        }
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        try {
            feed.commit();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public int parse(String s) {
        try {
            return Integer.parseInt(s);
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    public String message(Exception cause) {
        try {
            throw cause;
        } catch (Exception e) {
            String msg = e.getMessage();
            return msg;
        }
    }
}
