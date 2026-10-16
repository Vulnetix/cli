package com.acme.docs;

public class ShareService {
    public boolean canEdit(Document mine, Document other) {
~>        if (mine.getOwnerId() == mine.getOwnerId()) {
            return true;
        }
        return other.isPublic();
    }
}
