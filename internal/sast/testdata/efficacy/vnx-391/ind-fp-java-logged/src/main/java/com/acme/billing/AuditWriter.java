package com.acme.billing;

import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AuditWriter {
    private static final Logger LOG = LoggerFactory.getLogger(AuditWriter.class);
    private final AuditSink sink;

    public AuditWriter(AuditSink sink) {
        this.sink = sink;
    }

    public void record(String event) {
        try {
            sink.append(event);
        } catch (IOException e) {
            // TODO add retry with backoff
            LOG.warn("audit append failed for {}", event, e);
        }
    }
}
