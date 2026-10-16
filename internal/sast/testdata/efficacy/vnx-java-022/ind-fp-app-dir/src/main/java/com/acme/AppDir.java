package com.acme;
import java.io.File;
public class AppDir {
    File data(String home) { return new File(home, "data/state.json"); }
    String note = "files in /tmp are cleaned nightly";
}
