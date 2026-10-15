package com.acme.doc;

public class TagChecker {
    /**
     * Checks a comment. A tag written as {@code @param foo} or
     * {@literal @return} in prose is not a tag of this method.
     *
     * @param comment the comment text
     * @return {@code true} if the tags match
     */
    public boolean check(String comment) {
        return comment.contains("@param");
    }

    /**
     * {@return the number of tags seen}
     */
    public int seen() {
        return 0;
    }
}
