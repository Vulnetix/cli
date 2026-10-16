package com.acme.io;

import java.util.Calendar;
import java.util.Deque;
import java.util.LinkedList;

public abstract class AbstractCodec {
    private byte[] key;
    private final StringBuilder transcript = new StringBuilder();
    private Calendar epoch = Calendar.getInstance();
    private final Deque<String> pending = new LinkedList<>();

    protected byte[] getKey() {
~>        return key;
    }

    public StringBuilder transcript() {
~>        return transcript;
    }

    protected Calendar getEpoch() {
~>        return this.epoch;
    }

    public Deque<String> pendingFrames() {
~>        return pending;
    }
}
