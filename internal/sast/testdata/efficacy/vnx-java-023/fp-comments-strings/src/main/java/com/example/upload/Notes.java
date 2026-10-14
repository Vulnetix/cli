package com.example.upload;

public class Notes {
    // file.transferTo(new File(dir, file.getOriginalFilename())) allows .jsp uploads
    /*
     * Files.copy(in, root.resolve(part.getSubmittedFileName()));
     */
    static final String TIP = "never call file.transferTo(new File(dir, file.getOriginalFilename()))";
}
