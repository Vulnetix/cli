package com.acme.upload;

public final class UploadLimits {
    private static final long MAX_UPLOAD_BYTES = 5_242_880L;
    public static final int RETRY_DELAY_MS = 2500;

    public boolean tooLarge(long size) {
        return size > MAX_UPLOAD_BYTES;
    }

    public String describe() {
        return "max " + MAX_UPLOAD_BYTES + " bytes, retry after " + RETRY_DELAY_MS;
    }

    public long budget(int files) {
        return MAX_UPLOAD_BYTES * files;
    }
}
