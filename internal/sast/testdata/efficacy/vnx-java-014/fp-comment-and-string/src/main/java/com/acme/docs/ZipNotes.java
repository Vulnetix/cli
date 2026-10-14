package com.acme.docs;

import java.util.zip.ZipEntry;

public class ZipNotes {
    void note(ZipEntry entry) {
        // never do new File(dest, entry.getName()) without a canonical check
        String hint = "new File(dest, entry.getName()) is zip slip";
        System.out.println(hint + entry.getName());
    }
}
