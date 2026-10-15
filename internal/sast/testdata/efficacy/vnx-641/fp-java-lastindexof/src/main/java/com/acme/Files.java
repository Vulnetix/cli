package com.acme;

public class Files {
    public static String ext(String fileName) {
        String e = fileName.substring(fileName.lastIndexOf(".") + 1);
        String host = url.substring(url.indexOf(".") + 1);
        boolean xml = FilenameUtils.getExtension(fileName).equals("xml");
        return e + host + xml;
    }
}
