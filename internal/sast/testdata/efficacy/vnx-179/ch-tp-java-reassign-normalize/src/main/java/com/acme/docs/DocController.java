package com.acme.docs;

import java.text.Normalizer;

public class DocController {
    public byte[] fetch(String title) throws Exception {
~>        if (title.indexOf("<script") >= 0) {
            throw new IllegalArgumentException("markup");
        }
        title = Normalizer.normalize(title, Normalizer.Form.NFKC);
        return render(title);
    }
}
